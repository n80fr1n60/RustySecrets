#![no_main]

use libfuzzer_sys::{
    arbitrary::{Arbitrary, Unstructured},
    fuzz_target,
};
use rusty_secrets::wrapped_secrets;

fuzz_target!(|data: &[u8]| {
    // ---
    let mut unstructured = Unstructured::new(data);
    if let (Ok(k), Ok(n)) = (
        u8::arbitrary(&mut unstructured),
        u8::arbitrary(&mut unstructured),
    ) {

        wrapped_secrets::split_secret(k, n, &data, None, false)
            .map_err(|err| err.into())
            .and_then(|ss| wrapped_secrets::recover_secret(&ss, false))
            .map(|_| ())
            .unwrap_or(())
    }
});
