macro_rules! cstr {
    ($lit:literal) => {{
        // this `const` item produces compile time errors = it performs the checks at compile time
        const CS: &'static std::ffi::CStr =
            match std::ffi::CStr::from_bytes_until_nul(concat!($lit, "\0").as_bytes()) {
                Ok(x) => x,
                Err(_) => panic!("string literal did not pass CStr checks"),
            };
        CS
    }};
}
