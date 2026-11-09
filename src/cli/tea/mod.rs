//! Bubble Tea-inspired Elm Architecture for CLI commands
//!
//! This module implements the Elm Architecture pattern (Model → Update → View)
//! for building CLI experiences in Rust.
//!
//! ## The Architecture
//!
//! ```text
//!     ┌───────────────────────────────────────┐
//!     │             User Input                │
//!     └─────────────────┬─────────────────────┘
//!                       │
//!                       ▼
//!     ┌───────────────────────────────────────┐
//!     │          Update (Msg → Model)          │
//!     └─────────────────┬─────────────────────┘
//!                       │
//!                       ▼
//!     ┌───────────────────────────────────────┐
//!     │               Model                   │
//!     └─────────────────┬─────────────────────┘
//!                       │
//!                       ▼
//!     ┌───────────────────────────────────────┐
//!     │          View (Model → String)         │
//!     └─────────────────┬─────────────────────┘
//!                       │
//!                       ▼
//!     ┌───────────────────────────────────────┐
//!     │           Terminal Output             │
//!     └───────────────────────────────────────┘
//! ```
//!
//! ## Example
//!
//! ```rust,no_run
//! use omg_lib::cli::tea::{Program, Model, Cmd};
//!
//! struct MyModel {
//!     count: usize,
//! }
//!
//! #[derive(Debug)]
//! enum MyMsg {
//!     Increment,
//!     Decrement,
//! }
//!
//! impl Model for MyModel {
//!     type Msg = MyMsg;
//!
//!     fn init(&self) -> Cmd<MyMsg> {
//!         Cmd::none()
//!     }
//!
//!     fn update(&mut self, msg: MyMsg) -> Cmd<MyMsg> {
//!         match msg {
//!             MyMsg::Increment => self.count += 1,
//!             MyMsg::Decrement => self.count = self.count.saturating_sub(1),
//!         }
//!         Cmd::none()
//!     }
//!
//!     fn view(&self) -> String {
//!         format!("Count: {}", self.count)
//!     }
//! }
//!
//! // Run the program
//! let model = MyModel { count: 0 };
//! Program::new(model).run();
//! ```

mod async_bridge;
pub(crate) use async_bridge::run_blocking_future;
mod cmd;
mod renderer;

// Model implementations
mod info_model;
mod status_model;
mod update_model;
mod wrappers;

pub use cmd::{Cmd, StyledTextConfig, TextStyle, View};
pub use renderer::Renderer;

/// Upper bound on command steps (`update` transitions, batch entries) a
/// single program run may process, so a model that echoes `Cmd::Msg` in a
/// cycle fails with an explicit error instead of hanging or overflowing the
/// stack.
const MAX_CMD_STEPS: usize = 100_000;

// Re-export configuration types for convenience

// Re-export models
pub use info_model::{InfoModel, InfoMsg, InfoSource};
pub use status_model::{StatusData, StatusModel, StatusMsg};
pub use update_model::UpdateType;

// Re-export wrappers for easy integration
pub use wrappers::{run_info_elm, run_status_elm};

use std::io;

/// The core Model trait - implements the Elm Architecture
///
/// Your application state should implement this trait to define
/// how it responds to messages and renders itself.
pub trait Model: Sized {
    /// The message type for this model
    type Msg: Send + std::fmt::Debug + 'static;

    /// Initialize the model - return an optional command to run
    #[must_use]
    fn init(&self) -> Cmd<Self::Msg> {
        Cmd::none()
    }

    /// Update the model in response to a message
    ///
    /// Returns an optional command to run after updating
    #[must_use]
    fn update(&mut self, msg: Self::Msg) -> Cmd<Self::Msg>;

    /// Render the model to a string for display
    fn view(&self) -> String;
}

/// A Bubble Tea-inspired Program
///
/// Programs run a Model through the Elm Architecture lifecycle,
/// handling initialization, updates, and rendering.
pub struct Program<M: Model> {
    model: M,
    renderer: Renderer,
}

impl<M: Model> Program<M> {
    /// Create a new Program with the given Model
    #[must_use]
    pub fn new(model: M) -> Self {
        Self {
            model,
            renderer: Renderer::new(),
        }
    }

    /// Run the program to completion
    ///
    /// This will:
    /// 1. Call `init()` on the model
    /// 2. Execute any initial commands
    /// 3. Process all messages until completion
    /// 4. Render the final view
    pub fn run(mut self) -> io::Result<()> {
        // Initialize
        let init_cmd = self.model.init();

        // Render initial view to show loading state
        self.render()?;
        self.renderer.flush()?;

        self.process_cmd(init_cmd)?;
        Ok(())
    }

    /// Process a single command
    ///
    /// Iterative with an explicit work stack and a step budget: message
    /// cycles surface as [`MAX_CMD_STEPS`] errors rather than unbounded
    /// recursion.
    fn process_cmd(&mut self, cmd: Cmd<M::Msg>) -> io::Result<()> {
        let mut steps = 0usize;
        let mut queue = vec![cmd];

        while let Some(cmd) = queue.pop() {
            steps += 1;
            if steps > MAX_CMD_STEPS {
                return Err(io::Error::other(
                    "command step budget exceeded (model update cycle?)",
                ));
            }
            match cmd {
                Cmd::None => {}
                Cmd::Msg(msg) => {
                    let next = self.model.update(msg);
                    self.render()?;
                    queue.push(next);
                }
                Cmd::Batch(cmds) => {
                    // Reversed pushes keep the original batch order (LIFO).
                    for cmd in cmds.into_iter().rev() {
                        queue.push(cmd);
                    }
                }
                Cmd::Exec(f) => {
                    let next = self.model.update(f());
                    self.render()?;
                    queue.push(next);
                }
                other @ Cmd::View(_) => execute_output_cmd(&mut self.renderer, other)?,
            }
        }
        Ok(())
    }

    /// Render the current view
    fn render(&mut self) -> io::Result<()> {
        let view = self.model.view();
        if view.trim().is_empty() {
            Ok(())
        } else {
            self.renderer.render(&view)
        }
    }
}

/// Execute the output-only variants of [`Cmd`] against a renderer.
///
/// Control-flow variants (`None`/`Msg`/`Batch`/`Exec`) are left to the caller.
/// `Cmd::Error` yields `Err` without printing. Process-level error reporting
/// has one owner, so a failing command is never rendered twice.
fn execute_output_cmd<M>(renderer: &mut Renderer, cmd: Cmd<M>) -> io::Result<()> {
    match cmd {
        Cmd::None | Cmd::Msg(_) | Cmd::Batch(_) | Cmd::Exec(_) => {}
        Cmd::View(view) => execute_view(renderer, view)?,
    }
    Ok(())
}

/// Render one [`View`] against a renderer. The single home for
/// presentation dispatch; both the Elm runtime and the fallback executor
/// route through here in spirit, each with its own error type.
fn execute_view(renderer: &mut Renderer, view: View) -> io::Result<()> {
    match view {
        View::PrintLn(output) => {
            renderer.println(&output)?;
        }
        View::Info(msg) => {
            renderer.info(&msg)?;
        }
        View::Success(msg) => {
            renderer.success(&msg)?;
        }
        View::Warning(msg) => {
            renderer.warning(&msg)?;
        }
        View::Error(msg) => return Err(io::Error::other(msg)),
        View::Header(title, body) => {
            renderer.header(&title, &body)?;
        }
        View::Card(title, content) => {
            renderer.card(&title, &content)?;
        }
        View::StyledText(config) => {
            // No style renderer in this path; print the text so it is not
            // silently dropped (matches the fallback renderer behavior).
            renderer.println(&config.text)?;
        }
        View::Spacer => {
            renderer.println("")?;
        }
    }
    Ok(())
}

/// Run a pre-built command tree against a fresh renderer without a model.
///
/// Unlike the println-based fallback executor, this honors the Elm rendering
/// path and treats `Cmd::Error` as program failure. The returned error reaches
/// the process-level reporter, which prints it exactly once.
/// Control-flow commands (`None`/`Msg`/`Batch`/`Exec`) carry no output here
/// and are ignored, matching the fallback executor's contract.
pub fn run_report(cmd: Cmd<()>) -> io::Result<()> {
    let mut renderer = Renderer::new();
    let mut queue = vec![cmd];
    while let Some(cmd) = queue.pop() {
        match cmd {
            // Unwrap batches so nested commands are processed in order.
            Cmd::Batch(cmds) => {
                for cmd in cmds.into_iter().rev() {
                    queue.push(cmd);
                }
            }
            other => execute_output_cmd(&mut renderer, other)?,
        }
    }
    renderer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Default)]
    struct CounterModel {
        count: usize,
    }

    #[derive(Debug, Clone)]
    enum CounterMsg {
        Increment,
        Decrement,
        Double,
    }

    impl Model for CounterModel {
        type Msg = CounterMsg;

        fn update(&mut self, msg: Self::Msg) -> Cmd<Self::Msg> {
            match msg {
                CounterMsg::Increment => {
                    self.count += 1;
                    if self.count.is_multiple_of(5) {
                        Cmd::info(format!("Reached {}!", self.count))
                    } else {
                        Cmd::none()
                    }
                }
                CounterMsg::Decrement => {
                    self.count = self.count.saturating_sub(1);
                    Cmd::none()
                }
                CounterMsg::Double => {
                    self.count *= 2;
                    Cmd::batch([
                        Cmd::info(format!("Doubled to {}", self.count)),
                        Cmd::success("Doubling complete!".to_string()),
                    ])
                }
            }
        }

        fn view(&self) -> String {
            format!("Current count: {}", self.count)
        }
    }

    #[test]
    fn test_counter_increment() {
        let mut model = CounterModel::default();
        assert_eq!(model.count, 0);

        let cmd = model.update(CounterMsg::Increment);
        assert_eq!(model.count, 1);
        assert!(matches!(cmd, Cmd::None));

        let cmd = model.update(CounterMsg::Increment);
        assert_eq!(model.count, 2);
        assert!(matches!(cmd, Cmd::None));
    }

    #[test]
    fn test_counter_info_at_milestone() {
        let mut model = CounterModel { count: 4 };
        let cmd = model.update(CounterMsg::Increment);
        assert_eq!(model.count, 5);
        // Should emit info command at milestone
        assert!(matches!(cmd, Cmd::View(cmd::View::Info(_))));
    }

    #[test]
    fn test_counter_double() {
        let mut model = CounterModel { count: 3 };
        let cmd = model.update(CounterMsg::Double);
        assert_eq!(model.count, 6);
        assert!(matches!(cmd, Cmd::Batch(_)));
    }

    #[test]
    fn test_counter_decrement() {
        let mut model = CounterModel { count: 1 };
        let cmd = model.update(CounterMsg::Decrement);
        assert_eq!(model.count, 0);
        assert!(matches!(cmd, Cmd::None));

        // Should saturate at 0
        let cmd = model.update(CounterMsg::Decrement);
        assert_eq!(model.count, 0);
        assert!(matches!(cmd, Cmd::None));
    }

    #[test]
    fn test_view() {
        let model = CounterModel { count: 42 };
        assert_eq!(model.view(), "Current count: 42");
    }

    struct RenderCountingModel {
        state: usize,
        rendered_states: std::sync::Arc<std::sync::Mutex<Vec<usize>>>,
    }

    impl Model for RenderCountingModel {
        type Msg = usize;

        fn init(&self) -> Cmd<Self::Msg> {
            Cmd::msg(1)
        }

        fn update(&mut self, state: Self::Msg) -> Cmd<Self::Msg> {
            self.state = state;
            if state == 1 { Cmd::msg(2) } else { Cmd::none() }
        }

        fn view(&self) -> String {
            self.rendered_states
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(self.state);
            String::new()
        }
    }

    #[test]
    fn program_renders_intermediate_model_states() {
        let rendered_states = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        Program::new(RenderCountingModel {
            state: 0,
            rendered_states: std::sync::Arc::clone(&rendered_states),
        })
        .run()
        .unwrap();

        assert_eq!(
            *rendered_states
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            [0, 1, 2]
        );
    }

    #[test]
    fn program_processes_nested_batch_and_exec_in_order() {
        struct RecordingModel(std::sync::Arc<std::sync::Mutex<Vec<usize>>>);

        impl Model for RecordingModel {
            type Msg = usize;

            fn init(&self) -> Cmd<usize> {
                Cmd::batch([Cmd::msg(1), Cmd::batch([Cmd::exec(|| 2), Cmd::msg(3)])])
            }

            fn update(&mut self, msg: usize) -> Cmd<usize> {
                self.0.lock().unwrap().push(msg);
                Cmd::none()
            }

            fn view(&self) -> String {
                String::new()
            }
        }

        let observed = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        Program::new(RecordingModel(std::sync::Arc::clone(&observed)))
            .run()
            .unwrap();
        assert_eq!(*observed.lock().unwrap(), [1, 2, 3]);
    }

    struct ErrorModel;

    impl Model for ErrorModel {
        type Msg = ();

        fn init(&self) -> Cmd<Self::Msg> {
            Cmd::error("package not found")
        }

        fn update(&mut self, (): Self::Msg) -> Cmd<Self::Msg> {
            Cmd::none()
        }

        fn view(&self) -> String {
            String::new()
        }
    }

    #[test]
    fn program_run_returns_err_on_cmd_error() {
        let err = Program::new(ErrorModel)
            .run()
            .expect_err("Cmd::Error must fail the program so the CLI exits non-zero");
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert!(
            err.to_string().contains("package not found"),
            "original command error must be preserved, got: {err}"
        );
    }

    /// A model that echoes `Cmd::Msg` forever must hit the step budget and
    /// fail explicitly instead of recursing until the stack overflows.
    struct EchoModel;

    impl Model for EchoModel {
        type Msg = ();

        fn init(&self) -> Cmd<Self::Msg> {
            // Seed the cycle: every update re-emits the same message.
            Cmd::msg(())
        }

        fn update(&mut self, (): Self::Msg) -> Cmd<Self::Msg> {
            Cmd::msg(())
        }

        fn view(&self) -> String {
            String::new()
        }
    }

    #[test]
    fn message_cycle_fails_with_budget_error_instead_of_overflowing() {
        let err = Program::new(EchoModel)
            .run()
            .expect_err("a Cmd::Msg cycle must be bounded, not hang or crash");
        assert!(
            err.to_string().contains("step budget"),
            "expected budget error, got: {err}"
        );
    }

    #[test]
    fn run_report_fails_on_cmd_error() {
        let err = run_report(Cmd::<()>::error("package 'x' is not installed"))
            .expect_err("run_report must propagate Cmd::Error as failure");
        assert!(err.to_string().contains("not installed"));
    }

    #[test]
    fn run_report_batches_stop_after_first_error() {
        // The suggestion after the error must not suppress the failure.
        let err = run_report(Cmd::<()>::batch([
            Cmd::error("Package 'x' is not installed"),
            Cmd::success("this line never runs"),
        ]))
        .expect_err("first Cmd::Error in a batch must fail the run");
        assert!(err.to_string().contains("not installed"));
    }
}
