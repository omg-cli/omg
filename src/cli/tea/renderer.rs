//! Renderer for Bubble Tea-style CLI output
//!
//! Handles styled output using the existing UI primitives.

use owo_colors::OwoColorize;
use std::io::{self, BufWriter, Write};

/// Renderer for CLI output with styling
///
/// The renderer handles all output operations using the existing
/// UI primitives for consistent styling across the application.
pub struct Renderer<W: Write = BufWriter<io::Stdout>> {
    writer: W,
    no_color: bool,
}

impl Default for Renderer {
    fn default() -> Self {
        Self::new()
    }
}

fn colors_disabled() -> bool {
    // Single source of truth: NO_COLOR handling, OMG_COLORS overrides, and
    // TTY detection live in the project style helper.
    !crate::cli::style::colors_enabled()
}

impl Renderer<BufWriter<io::Stdout>> {
    /// Create a new renderer writing to stdout
    #[must_use]
    pub fn new() -> Self {
        Self {
            writer: BufWriter::new(io::stdout()),
            no_color: colors_disabled(),
        }
    }
}

impl<W: Write> Renderer<W> {
    /// Create a renderer with a custom writer
    #[must_use]
    pub fn with_writer(writer: W) -> Self {
        Self {
            writer,
            no_color: colors_disabled(),
        }
    }

    /// Flush the buffer
    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    /// Print text with newline
    pub fn println(&mut self, text: &str) -> io::Result<()> {
        writeln!(self.writer, "{text}")
    }

    /// Render a view (full output string)
    pub fn render(&mut self, view: &str) -> io::Result<()> {
        self.println(view)?;
        self.flush()
    }

    /// Print an info message
    pub fn info(&mut self, msg: &str) -> io::Result<()> {
        if self.no_color {
            writeln!(self.writer, "  ℹ {msg}")
        } else {
            writeln!(self.writer, "  {} {}", "ℹ".blue().bold(), msg)
        }
    }

    /// Print a success message
    pub fn success(&mut self, msg: &str) -> io::Result<()> {
        if self.no_color {
            writeln!(self.writer, "  ✓ {msg}")
        } else {
            writeln!(self.writer, "  {} {}", "✓".green().bold(), msg)
        }
    }

    /// Print a warning message
    pub fn warning(&mut self, msg: &str) -> io::Result<()> {
        if self.no_color {
            writeln!(self.writer, "  ⚠ {msg}")
        } else {
            writeln!(self.writer, "  {} {}", "⚠".yellow().bold(), msg)
        }
    }

    /// Print an error message
    pub fn error(&mut self, msg: &str) -> io::Result<()> {
        if self.no_color {
            writeln!(self.writer, "  ✗ {msg}")
        } else {
            writeln!(self.writer, "  {} {}", "✗".red().bold(), msg)
        }
    }

    /// Print a styled header
    pub fn header(&mut self, title: &str, body: &str) -> io::Result<()> {
        writeln!(
            self.writer,
            "{}",
            crate::cli::modern_ui::phase_header_text(title, body)
        )
    }

    /// Print a styled card with content.
    ///
    /// Rendered into the buffered writer (never straight to stdout) so output
    /// stays ordered relative to other commands sharing this renderer.
    pub fn card(&mut self, title: &str, content: &[String]) -> io::Result<()> {
        use comfy_table::Table;
        use comfy_table::modifiers::UTF8_ROUND_CORNERS;
        use comfy_table::presets::UTF8_FULL;

        let mut table = Table::new();
        let rendered_title = if self.no_color {
            title.to_string()
        } else {
            crate::cli::ui::Style::new().bold(true).render(title)
        };
        table
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .set_header(vec![rendered_title]);
        for line in content {
            table.add_row(vec![line.clone()]);
        }
        writeln!(self.writer, "\n{table}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_renderer_println() {
        let mut cursor = Cursor::new(Vec::new());
        let mut renderer = Renderer::with_writer(&mut cursor);

        renderer.println("hello").unwrap();
        renderer.println("world").unwrap();

        let output = String::from_utf8(cursor.into_inner()).unwrap();
        assert_eq!(output, "hello\nworld\n");
    }

    #[test]
    fn test_renderer_flush() {
        struct SharedSink(std::rc::Rc<std::cell::RefCell<Vec<u8>>>);

        impl Write for SharedSink {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.borrow_mut().write(bytes)
            }

            fn flush(&mut self) -> io::Result<()> {
                self.0.borrow_mut().flush()
            }
        }

        struct FlushFailure;

        impl Write for FlushFailure {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                io::sink().write(bytes)
            }

            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "literal fixture flush failure",
                ))
            }
        }

        let mut cursor = Cursor::new(Vec::new());
        let mut renderer = Renderer::with_writer(&mut cursor);

        renderer.println("test").unwrap();
        renderer.flush().unwrap();

        let output = String::from_utf8(cursor.into_inner()).unwrap();
        assert_eq!(output, "test\n");

        let published = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let buffered = BufWriter::new(SharedSink(std::rc::Rc::clone(&published)));
        let mut buffered_renderer = Renderer::with_writer(buffered);
        buffered_renderer.println("test").unwrap();
        assert!(
            published.borrow().is_empty(),
            "the fixture must buffer bytes before the explicit renderer flush"
        );
        buffered_renderer.flush().unwrap();
        assert_eq!(
            published.borrow().as_slice(),
            b"test\n",
            "renderer flush must publish the buffered bytes while the writer is alive"
        );

        let mut failing_renderer = Renderer::with_writer(FlushFailure);
        failing_renderer
            .println("write succeeds before flush failure")
            .unwrap();
        let error = failing_renderer
            .flush()
            .expect_err("renderer flush must preserve the writer error");
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(error.to_string(), "literal fixture flush failure");
    }

    #[test]
    fn card_does_not_emit_ansi_when_no_color_is_set() {
        temp_env::with_var("NO_COLOR", Some("1"), || {
            let mut cursor = Cursor::new(Vec::new());
            let mut renderer = Renderer::with_writer(&mut cursor);
            renderer
                .card("Title", &["content".to_string()])
                .expect("card renders");
            let output = String::from_utf8(cursor.into_inner()).expect("UTF-8 output");
            assert!(!output.contains('\u{1b}'));
        });
    }

    #[test]
    fn header_uses_a_bar_instead_of_a_filled_badge() {
        temp_env::with_var("NO_COLOR", Some("1"), || {
            let mut cursor = Cursor::new(Vec::new());
            let mut renderer = Renderer::with_writer(&mut cursor);
            renderer
                .header("Why", "for pacman")
                .expect("header renders");
            let output = String::from_utf8(cursor.into_inner()).expect("UTF-8 output");
            assert!(output.contains("Why"));
            assert!(output.contains("for pacman"));
            assert!(output.contains('|') || output.contains('┃'));
            assert!(!output.contains("📦"));
        });
    }

    #[test]
    fn test_render_view() {
        let mut cursor = Cursor::new(Vec::new());
        let mut renderer = Renderer::with_writer(&mut cursor);

        renderer.render("Current count: 42").unwrap();

        let output = String::from_utf8(cursor.into_inner()).unwrap();
        assert_eq!(output, "Current count: 42\n");
    }

    #[test]
    fn test_info_message() {
        let mut cursor = Cursor::new(Vec::new());
        let mut renderer = Renderer::with_writer(&mut cursor);

        renderer.info("Processing...").unwrap();

        let output = String::from_utf8(cursor.into_inner()).unwrap();
        assert!(output.contains("Processing"));
    }

    #[test]
    fn test_success_message() {
        let mut cursor = Cursor::new(Vec::new());
        let mut renderer = Renderer::with_writer(&mut cursor);

        renderer.success("Done!").unwrap();

        let output = String::from_utf8(cursor.into_inner()).unwrap();
        assert!(output.contains("Done"));
    }

    /// Regression: card/step/kv/list/tip used to write straight to stdout,
    /// letting a buffered `println` from an earlier command appear *after*
    /// the card. Everything must flow through the writer in call order.
    #[test]
    fn card_and_println_stay_in_call_order_through_the_writer() {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut renderer = Renderer::with_writer(&mut cursor);
            renderer.println("before").unwrap();
            renderer.card("My Card", &["row".to_string()]).unwrap();
            renderer.println("after").unwrap();
            renderer.flush().unwrap();
        }
        let output = String::from_utf8(cursor.into_inner()).unwrap();
        let before = output.find("before").expect("println output present");
        let card = output.find("My Card").expect("card present");
        let after = output.find("after").expect("trailing println present");
        assert!(before < card && card < after, "out of order: {output:?}");
    }
}
