use ecvrf;
use rug::{integer::Order, Integer};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;

// state & target should already be modulo
pub fn validate_difficulty(state: &Integer, target: &Integer) -> bool {
    let mut hasher = Sha256::new();
    // only hash state for demo purpose, in real-world case, we may need to add other block metadata
    hasher.update(state.to_digits::<u8>(Order::Lsf));
    let hashed = Integer::from_digits(&hasher.finalize(), Order::Lsf);
    (hashed.cmp(target) == Ordering::Less) || (hashed.cmp(target) == Ordering::Equal)
}

/// int(H("pubkey"||pubkey||"residue"||x)) mod N
pub fn h_g(modulus: &Integer, pubkey: &ecvrf::VrfPk, seed: &Integer) -> Integer {
    let mut hasher = Sha256::new();
    hasher.update("pubkey".as_bytes());
    hasher.update(pubkey.to_bytes());
    hasher.update("residue".as_bytes());
    hasher.update(seed.to_digits::<u8>(Order::Lsf));
    let hashed = Integer::from_digits(&hasher.finalize(), Order::Lsf);

    // invert to get enough security bits
    match hashed.invert(modulus) {
        Ok(inverse) => inverse,
        Err(unchanged) => unchanged,
    }
}

/// int(H("pubkey"||pubkey||"state"||state)) mod N
pub fn h_state(modulus: &Integer, pubkey: &ecvrf::VrfPk, state: &Integer) -> Integer {
    let mut hasher = Sha256::new();
    hasher.update("pubkey".as_bytes());
    hasher.update(pubkey.to_bytes());
    hasher.update("state".as_bytes());
    hasher.update(state.to_digits::<u8>(Order::Lsf));
    let hashed = Integer::from_digits(&hasher.finalize(), Order::Lsf);

    // invert to get enough security bits
    match hashed.invert(modulus) {
        Ok(inverse) => inverse,
        Err(unchanged) => unchanged,
    }
}

pub fn hash_to_prime(modulus: &Integer, inputs: &[&Integer]) -> Integer {
    let mut hasher = Sha256::new();
    for input in inputs {
        hasher.update(input.to_digits::<u8>(Order::Lsf));
        hasher.update("\n".as_bytes());
    }
    let hashed = Integer::from_digits(&hasher.finalize(), Order::Lsf);

    // invert to get enough security bits
    let inverse = match hashed.invert(modulus) {
        Ok(inverse) => inverse,
        Err(unchanged) => unchanged,
    };

    inverse.next_prime().div_rem_floor(modulus.clone()).1
}

// Fiat–Shamir heuristic non-iterative signature
pub fn hash_fs(modulus: &Integer, inputs: &[&Integer]) -> Integer {
    let mut hasher = Sha256::new();
    for input in inputs {
        hasher.update(input.to_digits::<u8>(Order::Lsf));
        hasher.update("\n".as_bytes());
    }
    let hashed = Integer::from_digits(&hasher.finalize(), Order::Lsf);

    // invert to get enough security bits
    match hashed.invert(modulus) {
        Ok(inverse) => inverse,
        Err(unchanged) => unchanged,
    }
}
