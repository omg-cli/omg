//! Commands for side effects in the Elm Architecture
//!
//! In Bubble Tea's Elm Architecture, Commands represent side effects
//! like I/O operations, timers, or async work. They're returned from
//! `update()` and processed by the runtime.

use crate::core::format::truncate;
use std::fmt;

/// A Command represents a side effect to execute
///
/// Commands are returned from `Model::update()` to trigger I/O,
/// output, or other side effects without breaking the pure functional
/// update cycle.
/// A presentation command: render-only output with no control-flow meaning.
///
/// Split from [`Cmd`] so control flow (None/Msg/Batch/Exec) and rendering
/// never share a match arm again. Every renderer handles `View`; only the
/// runtime handles `Cmd`.
#[derive(Debug, Clone)]
pub enum View {
    /// Print output with newline
    PrintLn(String),

    /// Print an info message (styled)
    Info(String),

    /// Print a success message (styled)
    Success(String),

    /// Print a warning message (styled)
    Warning(String),

    /// Print an error message (styled)
    Error(String),

    /// Print a styled header
    Header(String, String),

    /// Print a styled card with content
    Card(String, Vec<String>),

    /// Render styled text with lip-gloss styles
    StyledText(StyledTextConfig),

    /// Print a blank line (spacer)
    Spacer,
}

impl<M> From<View> for Cmd<M> {
    fn from(view: View) -> Self {
        Self::View(view)
    }
}

pub enum Cmd<M> {
    /// No operation - return this when there's no side effect
    None,

    /// Send a message back to the model
    Msg(M),

    /// Execute multiple commands in sequence
    Batch(Vec<Cmd<M>>),

    /// Execute a function that produces a message
    Exec(Box<dyn FnOnce() -> M>),

    /// Render output
    View(View),
}

impl<M> fmt::Debug for Cmd<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "Cmd::None"),
            Self::Msg(_) => write!(f, "Cmd::Msg(...)"),
            Self::Batch(batch) => f.debug_tuple("Batch").field(&batch.len()).finish(),
            Self::Exec(_) => write!(f, "Cmd::Exec(...)"),
            Self::View(View::PrintLn(s)) => {
                f.debug_tuple("PrintLn").field(&truncate(s, 20)).finish()
            }
            Self::View(View::Info(s)) => f.debug_tuple("Info").field(&truncate(s, 20)).finish(),
            Self::View(View::Success(s)) => {
                f.debug_tuple("Success").field(&truncate(s, 20)).finish()
            }
            Self::View(View::Warning(s)) => {
                f.debug_tuple("Warning").field(&truncate(s, 20)).finish()
            }
            Self::View(View::Error(s)) => f.debug_tuple("Error").field(&truncate(s, 20)).finish(),
            Self::View(View::Header(t, _)) => f.debug_tuple("Header").field(t).finish(),
            Self::View(View::Card(t, _)) => f.debug_tuple("Card").field(t).finish(),
            Self::View(View::StyledText(_)) => write!(f, "Cmd::StyledText(...)"),
            Self::View(View::Spacer) => write!(f, "Cmd::Spacer"),
        }
    }
}

/// Configuration for styled text
#[derive(Debug, Clone)]
pub struct StyledTextConfig {
    /// The text content
    pub text: String,
    /// Text style
    pub style: TextStyle,
}

/// Text styling options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextStyle {
    /// Bold text
    Bold,
    /// Success color (green)
    Success,
    /// Info color (blue)
    Info,
    /// Muted color (gray)
    Muted,
}

impl<M> Cmd<M> {
    /// Create a no-op command
    #[must_use]
    pub const fn none() -> Self {
        Self::None
    }

    /// Create a message command
    #[must_use]
    pub fn msg(msg: M) -> Self {
        Self::Msg(msg)
    }

    /// Batch multiple commands together
    #[must_use]
    pub fn batch(cmds: impl IntoIterator<Item = Cmd<M>>) -> Self {
        Self::Batch(cmds.into_iter().collect())
    }

    /// Execute a function that returns a message
    #[must_use]
    pub fn exec<F>(f: F) -> Self
    where
        F: FnOnce() -> M + 'static,
    {
        Self::Exec(Box::new(f))
    }

    /// Print with newline
    #[must_use]
    pub fn println(s: impl Into<String>) -> Self {
        Self::View(View::PrintLn(s.into()))
    }

    /// Print an info message
    #[must_use]
    pub fn info(s: impl Into<String>) -> Self {
        Self::View(View::Info(s.into()))
    }

    /// Print a success message
    #[must_use]
    pub fn success(s: impl Into<String>) -> Self {
        Self::View(View::Success(s.into()))
    }

    /// Print a warning message
    #[must_use]
    pub fn warning(s: impl Into<String>) -> Self {
        Self::View(View::Warning(s.into()))
    }

    /// Print an error message
    #[must_use]
    pub fn error(s: impl Into<String>) -> Self {
        Self::View(View::Error(s.into()))
    }

    /// Print a styled header
    #[must_use]
    pub fn header(title: impl Into<String>, body: impl Into<String>) -> Self {
        Self::View(View::Header(title.into(), body.into()))
    }

    /// Print a styled card with content
    #[must_use]
    pub fn card(title: impl Into<String>, content: Vec<String>) -> Self {
        Self::View(View::Card(title.into(), content))
    }

    /// Render styled text
    #[must_use]
    pub fn styled_text(config: StyledTextConfig) -> Self {
        Self::View(View::StyledText(config))
    }

    /// Render simple bold text
    #[must_use]
    pub fn bold(text: impl Into<String>) -> Self {
        Self::View(View::StyledText(StyledTextConfig {
            text: text.into(),
            style: TextStyle::Bold,
        }))
    }

    /// Print a blank line (spacer)
    #[must_use]
    pub fn spacer() -> Self {
        Self::View(View::Spacer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cmd_none() {
        let cmd: Cmd<()> = Cmd::none();
        assert!(matches!(cmd, Cmd::None));
    }

    #[test]
    fn test_cmd_msg() {
        let cmd: Cmd<String> = Cmd::msg("hello".to_string());
        assert!(matches!(cmd, Cmd::Msg(message) if message == "hello"));
    }

    #[test]
    fn test_cmd_batch() {
        let cmd: Cmd<()> = Cmd::batch([Cmd::println("a"), Cmd::println("b"), Cmd::none()]);
        let Cmd::Batch(commands) = cmd else {
            panic!("expected an ordered batch");
        };
        assert!(matches!(
            commands.as_slice(),
            [Cmd::View(View::PrintLn(first)), Cmd::View(View::PrintLn(second)), Cmd::None]
                if first == "a" && second == "b"
        ));
    }

    #[test]
    fn test_cmd_exec() {
        let cmd: Cmd<String> = Cmd::exec(|| "result".to_string());
        let Cmd::Exec(execute) = cmd else {
            panic!("expected an executable command");
        };
        assert_eq!(execute(), "result");
    }

    #[test]
    fn test_cmd_print_variants() {
        assert!(
            matches!(Cmd::<()>::println("test"), Cmd::View(View::PrintLn(text)) if text == "test")
        );
        assert!(matches!(Cmd::<()>::info("test"), Cmd::View(View::Info(text)) if text == "test"));
        assert!(
            matches!(Cmd::<()>::success("test"), Cmd::View(View::Success(text)) if text == "test")
        );
        assert!(
            matches!(Cmd::<()>::warning("test"), Cmd::View(View::Warning(text)) if text == "test")
        );
        assert!(matches!(Cmd::<()>::error("test"), Cmd::View(View::Error(text)) if text == "test"));
    }

    #[test]
    fn test_cmd_header() {
        let cmd: Cmd<()> = Cmd::header("Title", "Body");
        assert!(
            matches!(cmd, Cmd::View(View::Header(title, body)) if title == "Title" && body == "Body")
        );
    }

    #[test]
    fn test_cmd_card() {
        let cmd: Cmd<()> = Cmd::card("Title", vec!["line1".to_string(), "line2".to_string()]);
        assert!(
            matches!(cmd, Cmd::View(View::Card(title, content)) if title == "Title" && content == ["line1", "line2"])
        );
    }
}
