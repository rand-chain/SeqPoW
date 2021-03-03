use ecvrf;
use elapsed::measure_time;
use rug::Integer;
use seq_pow::{sloth, util};

/// Example modulus as a big prime number (M13 prime), see https://www.rieselprime.de/ziki/List_of_known_Mersenne_primes
pub const MODULUS: &str = "6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151";

/// An example of SeqPoW with time measurements.
fn main() {
    let modulus = Integer::from_str_radix(MODULUS, 10).unwrap();

    // use 256-bit for block header hash
    const PREV_BLOCK_HASH: &str =
        "1eeb30c7163271850b6d018e8282093ac6755a771da6267edf6c9b4fce9242ba";
    const TARGET_HASH: &str = "07fb30c7163271850b6d018e8282093ac6755a771da6267edf6c9b4fce9242ba";
    const NUM_STEPS: u64 = 2;

    let seed_hash = Integer::from_str_radix(PREV_BLOCK_HASH, 16).unwrap();
    let seed = Integer::from(seed_hash.div_rem_floor(modulus.clone()).1);
    println!("seed:\t\t0x{:064x}", seed);

    let target_hash = Integer::from_str_radix(TARGET_HASH, 16).unwrap();
    let target = Integer::from(target_hash.div_rem_floor(modulus.clone()).1);
    println!("target:\t\t0x{:064x}", target);
    println!("");

    let (_, pubkey) = ecvrf::keygen();
    let g = util::h_g(&modulus, &pubkey, &seed);
    println!("start mining...");
    let (elapsed, (state, iters)) =
        measure_time(|| sloth::mine(NUM_STEPS, &pubkey, &modulus, &g, &target));
    println!("found nonce:\t{}", iters);
    println!("witness:\t0x{:x}", &state);
    println!("elapsed:\t{}", elapsed);
    println!("");

    println!("verifying SeqPoW proof...");
    let (elapsed, is_verified) =
        measure_time(|| sloth::verify(&modulus, &seed, iters, &state, &pubkey, &target));
    println!("verified:\t{}", is_verified);
    println!("elapsed:\t{}", elapsed);

    assert!(is_verified)
}
