//! Copying a password to the clipboard and clearing it again after a timeout.

use std::io::Write;
use std::time::Duration;

use anyhow::{Context, Result};
use pwv_core::crypto::fingerprint;
use zeroize::Zeroizing;

/// How often the countdown wakes up.
const TICK: Duration = Duration::from_millis(100);

/// The system clipboard, behind a trait so that tests never touch the real one.
pub trait Clipboard {
    /// Replaces the clipboard contents with `text`.
    fn set(&mut self, text: &str) -> Result<()>;
    /// The current text, or an error if the clipboard holds no text.
    fn get(&mut self) -> Result<Zeroizing<String>>;
    /// Empties the clipboard.
    fn clear(&mut self) -> Result<()>;
}

/// The real clipboard, through `arboard`.
pub struct ArboardClipboard(arboard::Clipboard);

impl ArboardClipboard {
    pub fn open() -> Result<Self> {
        let inner = arboard::Clipboard::new().context(
            "cannot open the clipboard; pass --show --no-clipboard to print the password instead",
        )?;
        Ok(Self(inner))
    }
}

impl Clipboard for ArboardClipboard {
    fn set(&mut self, text: &str) -> Result<()> {
        Ok(self.0.set().text(text)?)
    }

    fn get(&mut self) -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new(self.0.get_text()?))
    }

    fn clear(&mut self) -> Result<()> {
        Ok(self.0.clear()?)
    }
}

/// Copies `text` and returns its SHA-256 fingerprint, so the clipboard can be checked later
/// without keeping the text.
pub fn copy(board: &mut impl Clipboard, text: &str) -> Result<[u8; 32]> {
    board.set(text).context("cannot copy to the clipboard")?;
    Ok(fingerprint(text.as_bytes()))
}

/// Counts down `timeout` on `out`, then clears the clipboard if it still holds the text whose
/// fingerprint is `copied`. Anything copied since is left alone. Returns whether it cleared.
pub fn clear_after(
    board: &mut impl Clipboard,
    copied: &[u8; 32],
    timeout: Duration,
    mut sleep: impl FnMut(Duration),
    out: &mut impl Write,
) -> Result<bool> {
    // Write errors are ignored: a closed stderr must never stop the clear.
    let mut left = timeout;
    let mut shown = None;
    while !left.is_zero() {
        let secs = left.as_secs() + u64::from(left.subsec_nanos() > 0);
        if shown != Some(secs) {
            let _ = write!(out, "\rClipboard clears in {secs:>3} s ");
            let _ = out.flush();
            shown = Some(secs);
        }
        let step = left.min(TICK);
        sleep(step);
        left -= step;
    }
    let unchanged = board
        .get()
        .is_ok_and(|now| fingerprint(now.as_bytes()) == *copied);
    if unchanged {
        board.clear().context("cannot clear the clipboard")?;
    }
    let message = if unchanged {
        "Clipboard cleared."
    } else {
        "Clipboard changed since the copy; left as it is."
    };
    let _ = writeln!(out, "\r{message:<50}");
    Ok(unchanged)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An in-memory clipboard.
    #[derive(Default)]
    struct FakeClipboard(Option<String>);

    impl Clipboard for FakeClipboard {
        fn set(&mut self, text: &str) -> Result<()> {
            self.0 = Some(text.to_owned());
            Ok(())
        }

        fn get(&mut self) -> Result<Zeroizing<String>> {
            self.0.clone().map(Zeroizing::new).context("no text")
        }

        fn clear(&mut self) -> Result<()> {
            self.0 = None;
            Ok(())
        }
    }

    /// Runs `clear_after` with a fake clock; returns (cleared, total slept, output).
    fn run(board: &mut FakeClipboard, copied: &[u8; 32], secs: u64) -> (bool, Duration, String) {
        let mut slept = Duration::ZERO;
        let mut out = Vec::new();
        let timeout = Duration::from_secs(secs);
        let cleared = clear_after(board, copied, timeout, |d| slept += d, &mut out).unwrap();
        (cleared, slept, String::from_utf8(out).unwrap())
    }

    #[test]
    fn clears_after_the_timeout_when_unchanged() {
        let mut board = FakeClipboard::default();
        let copied = copy(&mut board, "hunter2").unwrap();
        assert_eq!(board.0.as_deref(), Some("hunter2"));
        let (cleared, slept, out) = run(&mut board, &copied, 30);
        assert!(cleared);
        assert_eq!(board.0, None);
        assert_eq!(slept, Duration::from_secs(30));
        assert!(!out.contains("hunter2"));
        assert!(out.contains("Clipboard cleared."));
    }

    #[test]
    fn counts_down_each_second_once() {
        let mut board = FakeClipboard::default();
        let copied = copy(&mut board, "hunter2").unwrap();
        let (_, _, out) = run(&mut board, &copied, 3);
        let shown: Vec<_> = out
            .split('\r')
            .filter(|s| s.contains("clears in"))
            .collect();
        assert_eq!(shown.len(), 3);
        assert!(shown[0].contains("  3 s") && shown[2].contains("  1 s"));
    }

    #[test]
    fn leaves_a_changed_clipboard_alone() {
        let mut board = FakeClipboard::default();
        let copied = copy(&mut board, "hunter2").unwrap();
        board.set("something the user copied").unwrap();
        let (cleared, _, out) = run(&mut board, &copied, 1);
        assert!(!cleared);
        assert_eq!(board.0.as_deref(), Some("something the user copied"));
        assert!(out.contains("left as it is"));
    }

    #[test]
    fn leaves_an_unreadable_clipboard_alone() {
        let mut board = FakeClipboard::default();
        let copied = copy(&mut board, "hunter2").unwrap();
        board.0 = None; // emptied, or now holding an image
        let (cleared, _, _) = run(&mut board, &copied, 1);
        assert!(!cleared);
    }
}
