use ecvrf;
use elapsed::measure_time;
use rug::Integer;
use seq_pow::{util, wes19};

/// RSA-2048 modulus, taken from [Wikipedia](https://en.wikipedia.org/wiki/RSA_numbers#RSA-2048).
pub const MODULUS: &str =
  "251959084756578934940271832400483985714292821262040320277771378360436620207075955562640185258807\
  8440691829064124951508218929855914917618450280848912007284499268739280728777673597141834727026189\
  6375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172\
  6546322822168699875491824224336372590851418654620435767984233871847744479207399342365848238242811\
  9816381501067481045166037730605620161967625613384414360383390441495263443219011465754445417842402\
  0924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951\
  378636564391212010397122822120720357";

/// An example of SeqPoW with time measurements.
fn main() {
    let modulus = Integer::from_str_radix(MODULUS, 10).unwrap();

    // use 256-bit for block header hash
    const PREV_BLOCK_HASH: &str =
        "1eeb30c7163271850b6d018e8282093ac6755a771da6267edf6c9b4fce9242ba";
    const TARGET_HASH: &str = "07fb30c7163271850b6d018e8282093ac6755a771da6267edf6c9b4fce9242ba";
    const NUM_STEPS: u64 = 10;

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
    let (elapsed, (y, pi, iters)) =
        measure_time(|| wes19::mine(NUM_STEPS, &pubkey, &modulus, &g, &target));
    println!("found nonce:\t{}", iters);
    println!("y:\t0x{:x}", &y);
    println!("pi:\t0x{:x}", &pi);
    println!("elapsed:\t{}", elapsed);
    println!("");

    println!("verifying SeqPoW proof...");
    let (elapsed, is_verified) =
        measure_time(|| wes19::verify(&modulus, &g, iters, &y, &pi, &pubkey, &target));
    println!("verified:\t{}", is_verified);
    println!("elapsed:\t{}", elapsed);

    assert!(is_verified)
}
