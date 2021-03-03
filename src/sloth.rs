/// Modular Square Roots-based Sequential Proof-of-Work (SeqPoW) implementation.
use super::util;
use ecvrf;
use rug::Integer;

pub fn mine(
    step: u64,
    pubkey: &ecvrf::VrfPk,
    modulus: &Integer,
    ini_state: &Integer,
    target: &Integer,
) -> (Integer, u64) {
    let mut cur_state = ini_state.clone();
    let mut iters: u64 = 0;

    loop {
        iters += step;
        let (new_state, diff_valid) = solve(modulus, &cur_state, step, pubkey, target);
        cur_state = new_state;
        if diff_valid {
            break;
        }
    }

    (cur_state.clone(), iters)
}

pub fn solve(
    modulus: &Integer,
    state: &Integer,
    step: u64,
    pubkey: &ecvrf::VrfPk,
    target: &Integer,
) -> (Integer, bool) {
    // Take state by moduli p
    let mut new_state = Integer::from(state.clone().div_rem_floor(modulus.clone()).1);

    // Exponent for square root calculation
    let exponent = (modulus.clone() + 1) / 4;

    for _ in 0..step {
        // Perform a slow modular square root extraction
        new_state.pow_mod_mut(&exponent, modulus).unwrap();
        // println!("new_state:\t\t0x{:064x}", new_state);
    }

    let hstate = util::h_state(modulus, pubkey, &new_state);
    (new_state, util::validate_difficulty(&hstate, target))
}

/// Verifies that mining function from given `seed` was calculated and produced a `witness`
pub fn verify(
    modulus: &Integer,
    seed: &Integer,
    total_num_steps: u64,
    witness: &Integer,
    pubkey: &ecvrf::VrfPk,
    target: &Integer,
) -> bool {
    let hstate = util::h_state(modulus, pubkey, witness);
    if !util::validate_difficulty(&hstate, target) {
        return false;
    }

    // Get instance of 2 in Integer format for performing of squares
    let square: Integer = 2u64.into();

    let mut cur_state = witness.clone();
    // Perform NUM_ITERS of sequential modular squares to perform a verification of the solution
    for _ in 0..total_num_steps {
        // Perform a simple and fast modular squaring
        cur_state.pow_mod_mut(&square, modulus).unwrap();

        let cur_state_inv = (-cur_state.clone()).div_rem_floor(modulus.clone()).1;

        if util::validate_difficulty(&util::h_state(modulus, pubkey, &cur_state), target)
            && util::validate_difficulty(&util::h_state(modulus, pubkey, &cur_state_inv), target)
        {
            return false;
        }
    }

    let g = util::h_g(modulus, pubkey, seed);
    (g == cur_state) || (g == (-cur_state).div_rem_floor(modulus.clone()).1)
}
