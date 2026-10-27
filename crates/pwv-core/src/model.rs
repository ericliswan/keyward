//! In-memory vault data model, serialised as the JSON plaintext described in `docs/DESIGN.md`.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// A secret text field (password or notes).
///
/// `Debug` prints `<redacted>` and the buffer is zeroized on drop. Copies made by
/// `serde_json` while parsing cannot be wiped; see the README limitations.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretText(Zeroizing<String>);

impl SecretText {
    /// Returns the secret. Keep the borrow short and never log it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<String> for SecretText {
    fn from(s: String) -> Self {
        Self(Zeroizing::new(s))
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_text_debug_is_redacted() {
        let s = SecretText::from("hunter2".to_owned());
        assert_eq!(format!("{s:?}"), "<redacted>");
        assert_eq!(s.expose(), "hunter2");
    }
}
