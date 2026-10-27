//! Times Argon2id key derivation for several parameter profiles, to calibrate the default.
//!
//! Run with `cargo run --release --example kdf_bench`.

use std::hint::black_box;
use std::time::{Duration, Instant};

use pwv_core::kdf::{self, KdfParams, SALT_LEN};
use secrecy::SecretString;

const RUNS: u32 = 3;

const fn params(m_cost_mib: u32, t_cost: u32, p_cost: u32) -> KdfParams {
    KdfParams {
        m_cost_kib: m_cost_mib * 1024,
        t_cost,
        p_cost,
    }
}

fn main() -> Result<(), pwv_core::Error> {
    if cfg!(debug_assertions) {
        eprintln!("warning: debug build, timings are meaningless; add --release");
    }
    let profiles = [
        ("floor (OWASP)", KdfParams::PRODUCTION_FLOOR),
        ("RFC 9106 #2", params(64, 3, 4)),
        ("RFC 9106 #2, one lane", params(64, 3, 1)),
        ("128 MiB", params(128, 3, 4)),
        ("default", KdfParams::PRODUCTION),
        ("512 MiB", params(512, 2, 4)),
    ];
    let password = SecretString::from("benchmark password");

    println!(
        "{:<22} {:>8} {:>2} {:>2} {:>9} {:>9}",
        "profile", "m (MiB)", "t", "p", "min (ms)", "max (ms)"
    );
    for (name, params) in profiles {
        let (mut min, mut max) = (Duration::MAX, Duration::ZERO);
        for _ in 0..RUNS {
            let start = Instant::now();
            black_box(kdf::derive_key(&password, &[0; SALT_LEN], &params)?);
            let elapsed = start.elapsed();
            min = min.min(elapsed);
            max = max.max(elapsed);
        }
        println!(
            "{name:<22} {:>8} {:>2} {:>2} {:>9} {:>9}",
            params.m_cost_kib / 1024,
            params.t_cost,
            params.p_cost,
            min.as_millis(),
            max.as_millis()
        );
    }
    Ok(())
}
