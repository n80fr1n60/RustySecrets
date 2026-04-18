#![no_main]

use libfuzzer_sys::{
    arbitrary::{Arbitrary, Unstructured},
    fuzz_target,
};
use rusty_secrets::dss::thss::*;

fuzz_target!(|data: &[u8]| {
    // ---
    let mut unstructured = Unstructured::new(data);
    if let (Ok(k), Ok(n)) = (
        u8::arbitrary(&mut unstructured),
        u8::arbitrary(&mut unstructured),
    ) {

        split_secret(k, n, &data, &None)
            .and_then(|ss| recover_secret(&ss))
            .map(|_| ())
            .unwrap_or(())
    }
});
