//! Questions for the user: hidden prompts on the terminal, or lines from stdin with
//! `--password-stdin`.

use std::io::{self, BufRead, Write};

use anyhow::{Context, Result, bail};
use secrecy::SecretString;
use zeroize::Zeroizing;

/// Reads answers from `input`. Secrets come from a hidden terminal prompt, or from `input`
/// too when `--password-stdin` is set.
pub struct Prompter<R> {
    input: R,
    password_stdin: bool,
}

impl Prompter<io::StdinLock<'static>> {
    /// Reads from this process's stdin.
    pub fn stdin(password_stdin: bool) -> Self {
        Self::new(io::stdin().lock(), password_stdin)
    }
}

impl<R: BufRead> Prompter<R> {
    pub fn new(input: R, password_stdin: bool) -> Self {
        Self {
            input,
            password_stdin,
        }
    }

    /// Asks for a secret without echoing it.
    pub fn secret(&mut self, label: &str) -> Result<SecretString> {
        let answer = if self.password_stdin {
            self.read_line()?
        } else {
            Zeroizing::new(
                rpassword::prompt_password(format!("{label}: "))
                    .context("cannot read a hidden answer from the terminal")?,
            )
        };
        Ok(SecretString::from(answer.as_str()))
    }

    /// Asks for a visible answer. The prompt goes to stderr so stdout stays clean.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used from the add command onwards")
    )]
    pub fn line(&mut self, label: &str) -> Result<String> {
        if !self.password_stdin {
            eprint!("{label}: ");
            io::stderr().flush()?;
        }
        Ok(String::from(self.read_line()?.as_str()))
    }

    /// One line without its line ending. The buffer is zeroized because it may hold a secret.
    fn read_line(&mut self) -> Result<Zeroizing<String>> {
        // Room for typical answers, so the buffer is not reallocated (leaving a copy) while reading.
        let mut buf = Zeroizing::new(String::with_capacity(1024));
        if self.input.read_line(&mut buf)? == 0 {
            bail!("unexpected end of input");
        }
        let len = buf.trim_end_matches(['\r', '\n']).len();
        buf.truncate(len);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn password_stdin_reads_one_line_per_answer() {
        let mut p = Prompter::new(&b"hunter2\r\nalice\n  spaced  \n"[..], true);
        assert_eq!(
            p.secret("Master password").unwrap().expose_secret(),
            "hunter2"
        );
        assert_eq!(p.line("Username").unwrap(), "alice");
        assert_eq!(p.secret("Password").unwrap().expose_secret(), "  spaced  ");
        let err = p.line("Notes").unwrap_err();
        assert_eq!(err.to_string(), "unexpected end of input");
    }

    #[test]
    fn last_line_without_newline_is_read() {
        let mut p = Prompter::new(&b"hunter2"[..], true);
        assert_eq!(
            p.secret("Master password").unwrap().expose_secret(),
            "hunter2"
        );
    }
}
