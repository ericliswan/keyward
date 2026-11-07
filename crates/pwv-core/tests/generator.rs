//! Generator behaviour through the public API, using the OS random number generator.

use pwv_core::generator::{AMBIGUOUS, GenError, MAX_LENGTH, MIN_LENGTH, PasswordOptions, password};

fn options(f: impl FnOnce(&mut PasswordOptions)) -> PasswordOptions {
    let mut o = PasswordOptions::default();
    f(&mut o);
    o
}

#[test]
fn lengths_across_the_allowed_range_are_exact() {
    for length in [MIN_LENGTH, 9, 20, 64, MAX_LENGTH] {
        let pw = password(&options(|o| o.length = length)).unwrap();
        assert_eq!(pw.expose().len(), length);
    }
}

#[test]
fn disabled_classes_never_appear() {
    let digits_only = options(|o| {
        o.lower = false;
        o.upper = false;
        o.symbols = false;
    });
    let letters_only = options(|o| {
        o.digits = false;
        o.symbols = false;
    });
    for _ in 0..200 {
        let pw = password(&digits_only).unwrap();
        assert!(pw.expose().bytes().all(|b| b.is_ascii_digit()));
        let pw = password(&letters_only).unwrap();
        assert!(pw.expose().bytes().all(|b| b.is_ascii_alphabetic()));
        assert!(pw.expose().bytes().any(|b| b.is_ascii_lowercase()));
        assert!(pw.expose().bytes().any(|b| b.is_ascii_uppercase()));
    }
}

#[test]
fn avoid_ambiguous_removes_lookalikes() {
    let o = options(|o| {
        o.length = MAX_LENGTH;
        o.avoid_ambiguous = true;
    });
    for _ in 0..50 {
        let pw = password(&o).unwrap();
        assert!(!pw.expose().chars().any(|c| AMBIGUOUS.contains(c)));
    }
}

#[test]
fn bad_options_return_typed_errors() {
    assert_eq!(
        password(&options(|o| o.length = MIN_LENGTH - 1)).unwrap_err(),
        GenError::Length
    );
    let none = options(|o| {
        o.lower = false;
        o.upper = false;
        o.digits = false;
        o.symbols = false;
    });
    assert_eq!(password(&none).unwrap_err(), GenError::NoClasses);
    assert_eq!(none.entropy_bits().unwrap_err(), GenError::NoClasses);
}

#[test]
fn passwords_do_not_repeat() {
    let a = password(&PasswordOptions::default()).unwrap();
    let b = password(&PasswordOptions::default()).unwrap();
    assert_ne!(a.expose(), b.expose());
}
