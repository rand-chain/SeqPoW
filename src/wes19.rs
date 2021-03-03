use super::util;
use ecvrf;
use rug::Integer;

pub fn mine(
    step: u64,
    pubkey: &ecvrf::VrfPk,
    modulus: &Integer,
    ini_state: &Integer,
    target: &Integer,
) -> (Integer, Integer, u64) {
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

    let pi = prove(modulus, ini_state, iters, &cur_state);

    (cur_state.clone(), pi, iters)
}

pub fn solve(
    modulus: &Integer,
    state: &Integer,
    step: u64,
    pubkey: &ecvrf::VrfPk,
    target: &Integer,
) -> (Integer, bool) {
    let mut y = state.clone();

    for _ in 0..step {
        y = y.clone() * y.clone();
        y = y.div_rem_floor(modulus.clone()).1;
    }

    let hstate = util::h_state(modulus, pubkey, &y);
    (y, util::validate_difficulty(&hstate, target))
}

pub fn prove(modulus: &Integer, g: &Integer, iterations: u64, y: &Integer) -> Integer {
    let l = util::hash_to_prime(modulus, &[g, y]);

    // algo_4 from the paper, long division
    // TODO: consider algo_5 instead
    let mut b: Integer;
    let mut r = Integer::from(1);
    let mut r2: Integer;
    let two = Integer::from(2);
    let mut pi = Integer::from(1);

    for _ in 0..iterations {
        r2 = r.clone() * two.clone();
        b = r2.clone().div_rem_floor(l.clone()).0;
        r = r2.clone().div_rem_floor(l.clone()).1;
        let pi_2 = pi.clone().pow_mod(&two, modulus).unwrap();
        let g_b = g.clone().pow_mod(&b, modulus).unwrap();
        pi = pi_2 * g_b;
    }

    Integer::from(pi.div_rem_floor(modulus.clone()).1)
}

pub fn verify(
    modulus: &Integer,
    g: &Integer,
    iterations: u64,
    y: &Integer,
    pi: &Integer,
    pubkey: &ecvrf::VrfPk,
    target: &Integer,
) -> bool {
    let hstate = util::h_state(modulus, pubkey, y);
    if !util::validate_difficulty(&hstate, target) {
        return false;
    }

    let l = util::hash_to_prime(modulus, &[g, y]);

    let r = Integer::from(2)
        .pow_mod(&Integer::from(iterations), &l)
        .unwrap();
    let pi_l = pi.clone().pow_mod(&l, modulus).unwrap();
    let g_r = g.clone().pow_mod(&r, modulus).unwrap();
    let pi_l_g_r = pi_l * g_r;

    Integer::from(pi_l_g_r.div_rem_floor(modulus.clone()).1) == y.clone()
}
