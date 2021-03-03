#[macro_use]
extern crate criterion;

use criterion::Criterion;
use rug::Integer;
use seq_pow::{sloth, util};

// FOR BENCHMARKING ONLY
// NO SECURITY CHECK
pub fn verify(
    modulus: &Integer,
    seed: &Integer,
    total_num_steps: u64,
    witness: &Integer,
    pubkey: &ecvrf::VrfPk,
    target: &Integer,
) -> bool {
    let hstate = util::h_state(modulus, pubkey, witness);
    // if !util::validate_difficulty(&hstate, target) {
    //     return false;
    // }
    util::validate_difficulty(&hstate, target);

    // Get instance of 2 in Integer format for performing of squares
    let square: Integer = 2u64.into();

    let mut cur_state = witness.clone();
    // Perform NUM_ITERS of sequential modular squares to perform a verification of the solution
    for _ in 0..total_num_steps {
        // Perform a simple and fast modular squaring
        cur_state.pow_mod_mut(&square, modulus).unwrap();

        let cur_state_inv = (-cur_state.clone()).div_rem_floor(modulus.clone()).1;

        // if util::validate_difficulty(&util::h_state(modulus, pubkey, &cur_state), target)
        //     && util::validate_difficulty(&util::h_state(modulus, pubkey, &cur_state_inv), target)
        // {
        //     return false;
        // }
        util::validate_difficulty(&util::h_state(modulus, pubkey, &cur_state), target)
            && util::validate_difficulty(&util::h_state(modulus, pubkey, &cur_state_inv), target);
    }

    let g = util::h_g(modulus, pubkey, seed);
    (g == cur_state) || (g == (-cur_state).div_rem_floor(modulus.clone()).1)
}

fn bench_sloth(c: &mut Criterion) {
    let bench_solve = |c: &mut Criterion,
                       num_steps: u64,
                       modulus: &Integer,
                       state: &Integer,
                       pubkey: &ecvrf::VrfPk,
                       target: &Integer| {
        c.bench_function(
            &format!("sloth::solve() with num_steps {}", num_steps),
            move |b| b.iter(|| sloth::solve(modulus, state, num_steps, pubkey, target)),
        );
    };
    let bench_verify = |c: &mut Criterion,
                        num_steps: u64,
                        modulus: &Integer,
                        g: &Integer,
                        witness: &Integer,
                        pubkey: &ecvrf::VrfPk,
                        target: &Integer| {
        c.bench_function(
            &format!("sloth::verify() with num_steps {}", num_steps),
            move |b| b.iter(|| verify(modulus, g, num_steps, witness, pubkey, target)),
        );
    };

    // (M13 prime)
    pub const MODULUS: &str = "6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151";
    let modulus = Integer::from_str_radix(MODULUS, 10).unwrap();

    // use 256-bit for block header hash
    const PREV_BLOCK_HASH: &str =
        "1eeb30c7163271850b6d018e8282093ac6755a771da6267edf6c9b4fce9242ba";
    const TARGET_HASH: &str = "07fb30c7163271850b6d018e8282093ac6755a771da6267edf6c9b4fce9242ba";

    let seed_hash = Integer::from_str_radix(PREV_BLOCK_HASH, 16).unwrap();
    let seed = Integer::from(seed_hash.div_rem_floor(modulus.clone()).1);
    println!("seed:\t\t0x{:064x}", seed);

    let target_hash = Integer::from_str_radix(TARGET_HASH, 16).unwrap();
    let target = Integer::from(target_hash.div_rem_floor(modulus.clone()).1);
    println!("target:\t\t0x{:064x}", target);
    println!("");

    let (_, pubkey) = ecvrf::keygen();
    let g = util::h_g(&modulus, &pubkey, &seed);
    let witness = g.clone(); // NVM this will definitely fail the verification...

    let num_steps_arr = [
        1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 64_000, 128_000, 256_000,
    ];

    for &num_steps in &num_steps_arr {
        bench_solve(c, num_steps, &modulus, &g, &pubkey, &target);
        bench_verify(c, num_steps, &modulus, &g, &witness, &pubkey, &target);
    }

    // for &total_num_steps in &[10_000, 20_000, 50_000, 100_000, 200_000, 400_000, 800_000, 1_600_000] {
    //     bench_verify(c, total_num_steps, &modulus, &g, &witness, &pubkey, &target);
    // }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_sloth
}
criterion_main!(benches);
