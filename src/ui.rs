//! Terminal styling for the setup wizard and `setup claude`: step headers, ✓/✗/⚠ marks,
//! dim hints and a small spinner. Colors go through `console` (the crate dialoguer uses), so
//! `NO_COLOR`, `CLICOLOR=0` and non-TTY output all give plain text without escape codes.

use std::future::Future;
use std::io::Write;
use std::time::Duration;

use console::Style;

#[derive(Debug, Clone, Copy)]
pub struct Ui {
    color: bool,
    /// stderr is a terminal (spinners and line clearing are allowed)
    tty: bool,
}

impl Ui {
    /// For output on stderr (where prompts go).
    pub fn stderr() -> Ui {
        let tty = console::Term::stderr().is_term();
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        if no_color {
            console::set_colors_enabled_stderr(false);
            console::set_colors_enabled(false);
        }
        Ui {
            color: tty && !no_color && console::colors_enabled_stderr(),
            tty,
        }
    }

    /// For output on stdout (`setup claude`, `init --list`).
    pub fn stdout() -> Ui {
        let tty = console::Term::stdout().is_term();
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        Ui {
            color: tty && !no_color && console::colors_enabled(),
            tty,
        }
    }

    pub fn plain() -> Ui {
        Ui {
            color: false,
            tty: false,
        }
    }

    pub fn is_tty(&self) -> bool {
        self.tty
    }

    fn paint(&self, s: &str, st: Style) -> String {
        if self.color {
            st.force_styling(true).apply_to(s).to_string()
        } else {
            s.to_string()
        }
    }

    pub fn dim(&self, s: &str) -> String {
        self.paint(s, Style::new().dim())
    }
    pub fn bold(&self, s: &str) -> String {
        self.paint(s, Style::new().bold())
    }
    pub fn accent(&self, s: &str) -> String {
        self.paint(s, Style::new().cyan())
    }
    pub fn green(&self, s: &str) -> String {
        self.paint(s, Style::new().green())
    }
    pub fn red(&self, s: &str) -> String {
        self.paint(s, Style::new().red())
    }
    pub fn yellow(&self, s: &str) -> String {
        self.paint(s, Style::new().yellow())
    }

    /// `✓ text` (green mark).
    pub fn ok(&self, s: &str) -> String {
        format!("{} {s}", self.green("✓"))
    }
    /// `✗ text` (red mark).
    pub fn bad(&self, s: &str) -> String {
        format!("{} {s}", self.red("✗"))
    }
    /// `⚠ text` (yellow mark).
    pub fn warn(&self, s: &str) -> String {
        format!("{} {s}", self.yellow("⚠"))
    }

    /// The step header: a title line and a thin rule.
    ///
    /// ```text
    ///   🛡  middleman setup                         step 1 of 4 · Where to install
    ///   ─────────────────────────────────────────────────────────────────────────
    /// ```
    pub fn header(&self, step: usize, total: usize, title: &str) -> String {
        let left = "🛡  middleman setup";
        let right = format!("step {step} of {total} · {title}");
        let width = if self.tty {
            (console::Term::stderr().size().1 as usize).clamp(40, 80)
        } else {
            72
        };
        let used = console::measure_text_width(left) + console::measure_text_width(&right) + 2;
        let gap = width.saturating_sub(used).max(3);
        format!(
            "\n  {}{}{}\n  {}",
            self.bold(left),
            " ".repeat(gap),
            self.accent(&right),
            self.dim(&"─".repeat(width.saturating_sub(2)))
        )
    }

    /// Two aligned columns, for summaries: `  label      value`.
    pub fn row(&self, label: &str, value: &str) -> String {
        format!("  {} {value}", self.bold(&format!("{label:<14}")))
    }

    /// Run `fut` while showing a spinner and `msg` (TTY only; otherwise one plain line).
    pub async fn spin<F: Future>(&self, msg: &str, fut: F) -> F::Output {
        if !self.tty {
            let _ = writeln!(std::io::stderr(), "  {msg}…");
            return fut.await;
        }
        const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        tokio::pin!(fut);
        let mut tick = tokio::time::interval(Duration::from_millis(90));
        let mut i = 0usize;
        let term = console::Term::stderr();
        let out = loop {
            tokio::select! {
                v = &mut fut => break v,
                _ = tick.tick() => {
                    let _ = term.clear_line();
                    let _ = write!(
                        std::io::stderr(),
                        "  {} {msg}…",
                        self.accent(FRAMES[i % FRAMES.len()])
                    );
                    let _ = std::io::stderr().flush();
                    i += 1;
                }
            }
        };
        let _ = term.clear_line();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_output_has_no_escape_codes() {
        let u = Ui::plain();
        let s = [
            u.ok("fine"),
            u.bad("broken"),
            u.warn("careful"),
            u.dim("hint"),
            u.header(1, 4, "Where to install"),
            u.row("Config", "~/.config/middleman/config.toml"),
        ]
        .join("\n");
        assert!(!s.contains('\x1b'), "{s:?}");
        assert!(s.contains("✓ fine") && s.contains("✗ broken") && s.contains("⚠ careful"));
        assert!(s.contains("step 1 of 4 · Where to install"));
    }

    #[tokio::test]
    async fn spinner_returns_the_value_without_a_tty() {
        assert_eq!(Ui::plain().spin("checking", async { 7 }).await, 7);
    }
}
