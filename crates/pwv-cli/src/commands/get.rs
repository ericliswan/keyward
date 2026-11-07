//! `pwv get`: copy an entry's password to the clipboard, or print it.

use std::io::{self, BufRead, IsTerminal};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::clipboard::{self, ArboardClipboard};
use crate::prompt::Prompter;

/// Copies the password and clears it after `clear_after`; with `None` the clipboard is not
/// touched. Flags are checked and the clipboard opened before unlocking, so a refused run never
/// costs a KDF.
pub fn run(
    path: &Path,
    site: &str,
    show: bool,
    force: bool,
    clear_after: Option<Duration>,
    prompt: &mut Prompter<impl BufRead>,
) -> Result<()> {
    if show && !force && !io::stdout().is_terminal() {
        bail!("stdout is not a terminal; pass --force to print the password anyway");
    }
    let board = match clear_after {
        Some(timeout) => Some((ArboardClipboard::open()?, timeout)),
        None => None,
    };
    let unlocked = super::unlock(path, prompt)?;
    let entry = super::choose(&unlocked.vault, site, prompt)?;
    if show {
        println!("{}", entry.password.expose());
    }
    let Some((mut board, timeout)) = board else {
        return Ok(());
    };
    // Installed only now, so Ctrl-C at a prompt still just quits. With the `termination` feature
    // it also catches SIGTERM and SIGHUP, such as a closed terminal window.
    static INTERRUPTED: AtomicBool = AtomicBool::new(false);
    ctrlc::set_handler(|| INTERRUPTED.store(true, Ordering::SeqCst))
        .context("cannot install the Ctrl-C handler")?;
    let copied = clipboard::copy(&mut board, entry.password.expose())?;
    eprintln!("Copied the password for {} to the clipboard.", entry.site);
    // The vault, and with it the password, is wiped before the wait.
    drop(unlocked);
    clipboard::clear_after(
        &mut board,
        &copied,
        timeout,
        &INTERRUPTED,
        thread::sleep,
        &mut io::stderr(),
    )?;
    Ok(())
}
