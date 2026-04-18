#![no_main]

use libfuzzer_sys::{
    arbitrary::{Arbitrary, Unstructured},
    fuzz_target,
};
use rusty_secrets::sss;

fuzz_target!(|data: &[u8]| {
    // ---
    let mut unstructured = Unstructured::new(data);
    if let (Ok(k), Ok(n)) = (
        u8::arbitrary(&mut unstructured),
        u8::arbitrary(&mut unstructured),
    ) {

        sss::split_secret(k, n, &data, false)
            .map_err(|err| err.into())
            .and_then(|ss| sss::recover_secret(&ss, false))
            .map(|_| ())
            .unwrap_or(())
    }
});
