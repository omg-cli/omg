//! Interactive first-run setup wizard for OMG.
//!
//! Reduces friction from install → first successful command to <2 minutes.

use anyhow::{Context, Result};
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
    terminal::{self, ClearType},
};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

/// RAII guard restoring terminal state even when a menu exits via `?` or an
/// early error; without it a failed `event::read()` leaves the tty in raw mode.
struct RawModeGuard;

impl RawModeGuard {
    fn enable() -> Result<Self> {
        terminal::enable_raw_mode()?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

/// Write a single menu option line in raw mode.
///
/// In raw mode, `\n` only moves the cursor down — it does NOT carriage-return
/// to column 0. macOS Terminal.app strictly follows this, causing menu options
/// to scatter across the screen. This helper uses `\r\n` and clears each line
/// before writing to ensure correct cross-platform rendering.
fn write_menu_line(stdout: &mut io::Stdout, text: &str, highlighted: bool) -> Result<()> {
    execute!(
        stdout,
        cursor::MoveToColumn(0),
        terminal::Clear(ClearType::CurrentLine)
    )?;
    if highlighted {
        execute!(
            stdout,
            SetForegroundColor(Color::Green),
            Print(text),
            Print("\r\n"),
            ResetColor
        )?;
    } else {
        execute!(stdout, Print(text), Print("\r\n"))?;
    }
    Ok(())
}

use crate::config::Settings;
use crate::core::sysinfo::{BuildRecommendation, SystemInfo};

fn is_menu_cancel_key(key: &KeyEvent) -> bool {
    key.code == KeyCode::Char('q')
        || (key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'd')))
}

/// Core interactive single-select menu loop shared by all wizard prompts.
///
/// Renders each option via `render` (highlighting the active row), then
/// handles ↑/↓ navigation, Enter to confirm, and q, Ctrl+C, or Ctrl+D to cancel. Raw mode is
/// enabled here and restored on every exit path via [`RawModeGuard`].
///
/// Non-press key events fall through to the `MoveUp` redraw instead of
/// `continue`-ing past it: skipping the move desynchronises the cursor and
/// makes the next redraw paint below the menu (observed on terminals that
/// emit release/repeat events).
fn run_menu<T: Copy>(
    stdout: &mut io::Stdout,
    options: &[T],
    initial: usize,
    render: impl Fn(&T) -> String,
) -> Result<T> {
    assert!(!options.is_empty(), "menu needs at least one option");
    let _raw = RawModeGuard::enable()?;
    let mut selected = initial.min(options.len() - 1);

    loop {
        for (i, opt) in options.iter().enumerate() {
            let label = render(opt);
            let text = if i == selected {
                format!("  ▸ {label}")
            } else {
                format!("    {label}")
            };
            write_menu_line(stdout, &text, i == selected)?;
        }

        stdout.flush()?;

        if let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            if is_menu_cancel_key(&key) {
                anyhow::bail!("Setup cancelled");
            }
            match key.code {
                KeyCode::Up => selected = selected.saturating_sub(1),
                KeyCode::Down => selected = (selected + 1).min(options.len() - 1),
                KeyCode::Enter => return Ok(options[selected]),
                _ => {}
            }
        }

        // Move cursor back up to redraw.
        execute!(stdout, cursor::MoveUp(options.len() as u16))?;
    }
}

/// Shell options for hook installation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    Zsh,
    Bash,
    Fish,
}

impl Shell {
    fn name(self) -> &'static str {
        match self {
            Shell::Zsh => "zsh",
            Shell::Bash => "bash",
            Shell::Fish => "fish",
        }
    }

    fn config_file(self) -> &'static str {
        match self {
            Shell::Zsh => "~/.zshrc",
            Shell::Bash => "~/.bashrc",
            Shell::Fish => "~/.config/fish/config.fish",
        }
    }

    fn hook_command(self) -> String {
        match self {
            Shell::Zsh => r#"eval "$(omg hook zsh)""#.to_string(),
            Shell::Bash => r#"eval "$(omg hook bash)""#.to_string(),
            Shell::Fish => "omg hook fish | source".to_string(),
        }
    }
}

/// Daemon startup options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonStartup {
    /// Start daemon on shell init (fastest, recommended)
    OnShellInit,
    /// Start daemon on first OMG command
    OnDemand,
    /// Use systemd user service
    Systemd,
    /// Don't auto-start daemon
    Manual,
}

fn effective_daemon_startup(selected: DaemonStartup, daemon_disabled: bool) -> DaemonStartup {
    if daemon_disabled {
        DaemonStartup::Manual
    } else {
        selected
    }
}

impl DaemonStartup {
    fn name(self) -> &'static str {
        match self {
            DaemonStartup::OnShellInit => "On shell init (fastest)",
            DaemonStartup::OnDemand => "On first OMG command",
            DaemonStartup::Systemd => "Systemd user service",
            DaemonStartup::Manual => "Manual (I'll start it myself)",
        }
    }
}

/// Wizard state
struct WizardState {
    shell: Option<Shell>,
    daemon_startup: DaemonStartup,
    telemetry_enabled: bool,
    build_config: Option<BuildRecommendation>,
    capture_env: bool,
}

impl Default for WizardState {
    fn default() -> Self {
        Self {
            shell: None,
            daemon_startup: DaemonStartup::OnShellInit,
            telemetry_enabled: false,
            build_config: None,
            capture_env: true,
        }
    }
}

/// Run the interactive setup wizard
pub async fn run_interactive(skip_shell: bool, skip_daemon: bool) -> Result<()> {
    // Check if we are in a non-interactive terminal (e.g. CI)
    if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        println!("Non-interactive terminal detected, running with defaults...");
        return run_defaults(skip_shell, skip_daemon).await;
    }

    let mut stdout = io::stdout();

    // Clear screen and show welcome
    execute!(
        stdout,
        terminal::Clear(ClearType::All),
        cursor::MoveTo(0, 0)
    )?;

    print_header(&mut stdout)?;
    println!();

    let mut state = WizardState::default();

    if !skip_shell {
        state.shell = Some(select_shell(&mut stdout)?);
        println!();
    }

    if !skip_daemon {
        state.daemon_startup = effective_daemon_startup(
            select_daemon_startup(&mut stdout)?,
            crate::core::client::DaemonClient::daemon_disabled(),
        );
        println!();
    }

    state.telemetry_enabled = select_telemetry_consent(&mut stdout)?;
    println!();

    state.build_config = select_build_config(&mut stdout)?;
    println!();

    state.capture_env = confirm_env_capture(&mut stdout)?;
    println!();

    // Apply configuration
    println!();
    execute!(
        stdout,
        SetForegroundColor(Color::Cyan),
        Print("═══════════════════════════════════════════════════════════\n"),
        Print("  Applying Configuration\n"),
        Print("═══════════════════════════════════════════════════════════\n"),
        ResetColor
    )?;
    println!();

    // Install shell hook (with daemon startup if user selected OnShellInit)
    if let Some(shell) = state.shell {
        let start_daemon_on_shell = state.daemon_startup == DaemonStartup::OnShellInit;
        install_shell_hook(&mut stdout, shell, start_daemon_on_shell)?;
    }

    // Configure daemon startup
    configure_daemon_startup(&mut stdout, state.daemon_startup)?;

    // Configure telemetry
    apply_telemetry_config(&mut stdout, state.telemetry_enabled)?;

    // Apply build configuration
    if let Some(ref config) = state.build_config {
        apply_build_config(&mut stdout, config)?;
    }

    // Capture environment
    if state.capture_env {
        capture_environment(&mut stdout).await?;
    }

    // Show completion message
    print_completion(&mut stdout, &state)?;

    Ok(())
}

fn select_telemetry_consent(stdout: &mut io::Stdout) -> Result<bool> {
    execute!(
        stdout,
        SetForegroundColor(Color::Cyan),
        Print("Step 3/5: "),
        ResetColor,
        Print("Telemetry & Anonymous Data\n")
    )?;
    execute!(
        stdout,
        SetForegroundColor(Color::DarkGrey),
        Print("  OMG collects anonymous data to help improve the tool.\n"),
        Print("  We collect: OMG version, OS/Arch, and a random install ID.\n"),
        Print("  We NEVER collect: personal info, filenames, or command args.\n"),
        ResetColor
    )?;
    println!();

    select_binary_menu(
        stdout,
        "Yes, I'd like to help improve OMG (anonymous)",
        "No, keep everything local",
    )
}

fn apply_telemetry_config(stdout: &mut io::Stdout, enabled: bool) -> Result<()> {
    execute!(
        stdout,
        Print("  "),
        SetForegroundColor(Color::Blue),
        Print("→"),
        ResetColor,
        Print(" Configuring telemetry...")
    )?;

    let _write_lock = Settings::write_lock()?;
    let mut settings = Settings::load().context("Failed to load OMG settings")?;
    settings.telemetry_enabled = enabled;

    if let Err(e) = settings.save() {
        execute!(
            stdout,
            SetForegroundColor(Color::Yellow),
            Print(format!(" (failed: {e})\n")),
            ResetColor
        )?;
    } else {
        let status = if enabled { "enabled" } else { "disabled" };
        execute!(
            stdout,
            SetForegroundColor(Color::Green),
            Print(format!(" ✓ ({status})\n")),
            ResetColor
        )?;
    }

    Ok(())
}

fn write_styled(stdout: &mut io::Stdout, color: Color, text: &str) -> Result<()> {
    if crate::cli::style::colors_enabled() {
        execute!(stdout, SetForegroundColor(color), Print(text), ResetColor)?;
    } else {
        write!(stdout, "{text}")?;
    }
    Ok(())
}

/// Run with defaults (non-interactive).
pub async fn run_defaults(skip_shell: bool, skip_daemon: bool) -> Result<()> {
    let mut stdout = io::stdout();

    println!();
    write_styled(&mut stdout, Color::Cyan, "OMG")?;
    println!(" Setting up with defaults...\n");

    let shell = if skip_shell {
        println!("  → Shell hook: skipped");
        None
    } else {
        let shell = detect_current_shell();
        if let Some(shell) = shell {
            install_shell_hook(&mut stdout, shell, false)?;
        }
        shell
    };

    if skip_daemon {
        println!("  → Daemon setup: skipped");
    } else {
        let daemon_disabled = crate::core::client::DaemonClient::daemon_disabled();
        configure_daemon_startup(
            &mut stdout,
            if daemon_disabled {
                DaemonStartup::Manual
            } else {
                DaemonStartup::OnDemand
            },
        )?;
    }

    capture_environment(&mut stdout).await?;

    println!();
    write_styled(&mut stdout, Color::Green, "✓")?;
    println!(" Setup complete!");
    if let Some(shell) = shell {
        println!("  Restart your shell to activate the hook.");
        println!("  Config updated: {}", shell.config_file());
    }

    Ok(())
}

fn print_header(stdout: &mut io::Stdout) -> Result<()> {
    execute!(
        stdout,
        SetForegroundColor(Color::Magenta),
        Print("╔═══════════════════════════════════════════════════════════╗\n"),
        Print("║"),
        SetForegroundColor(Color::White),
        Print("              🚀 Welcome to OMG Setup                      "),
        SetForegroundColor(Color::Magenta),
        Print("║\n"),
        Print("║"),
        SetForegroundColor(Color::DarkGrey),
        Print("    The Fastest Unified Package Manager for Linux          "),
        SetForegroundColor(Color::Magenta),
        Print("║\n"),
        Print("╚═══════════════════════════════════════════════════════════╝\n"),
        ResetColor
    )?;
    println!();
    println!("  This wizard will configure OMG in about 60 seconds.");
    println!("  Use ↑/↓ to navigate, Enter to select, q to quit.");
    Ok(())
}

fn detect_current_shell() -> Option<Shell> {
    // Method 1: Check $SHELL environment variable (user's default shell)
    if let Ok(shell) = std::env::var("SHELL")
        && let Some(s) = parse_shell_path(&shell)
    {
        return Some(s);
    }

    // Method 2: Check parent process (actual running shell)
    #[cfg(unix)]
    if let Some(s) = detect_shell_from_parent_process() {
        return Some(s);
    }

    // Method 3: Check /etc/passwd for user's configured shell
    #[cfg(unix)]
    if let Ok(user) = std::env::var("USER")
        && let Ok(passwd) = std::fs::read_to_string("/etc/passwd")
    {
        for line in passwd.lines() {
            if line.starts_with(&format!("{user}:"))
                && let Some(shell_path) = line.split(':').next_back()
                && let Some(s) = parse_shell_path(shell_path)
            {
                return Some(s);
            }
        }
    }

    None
}

/// Parse a shell path and return the Shell enum
fn parse_shell_path(path: &str) -> Option<Shell> {
    let shell_name = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path);

    match shell_name {
        "zsh" => Some(Shell::Zsh),
        "bash" => Some(Shell::Bash),
        "fish" => Some(Shell::Fish),
        _ => None,
    }
}

/// Detect shell from the parent process (the actual running shell, not the
/// login default).
#[cfg(unix)]
fn detect_shell_from_parent_process() -> Option<Shell> {
    use std::fs;

    // Get the PARENT process id; std::process::id() would read our own
    // /proc entry, which is always "omg" and can never match a shell.
    let ppid = rustix::process::getppid()?;
    let ppid = rustix::process::Pid::as_raw(Some(ppid));

    // Try to read /proc/{ppid}/comm or /proc/{ppid}/cmdline
    if let Ok(comm) = fs::read_to_string(format!("/proc/{ppid}/comm"))
        && let Some(s) = parse_shell_path(comm.trim())
    {
        return Some(s);
    }

    // Fallback: check cmdline
    if let Ok(cmdline) = fs::read_to_string(format!("/proc/{ppid}/cmdline"))
        && let Some(s) = parse_shell_path(cmdline.split('\0').next().unwrap_or(""))
    {
        return Some(s);
    }

    None
}

fn select_shell(stdout: &mut io::Stdout) -> Result<Shell> {
    let detected = detect_current_shell();
    let shells = [Shell::Zsh, Shell::Bash, Shell::Fish];
    let initial = detected.map_or(0, |d| shells.iter().position(|&s| s == d).unwrap_or(0));

    execute!(
        stdout,
        SetForegroundColor(Color::Cyan),
        Print("Step 1/5: "),
        ResetColor,
        Print("Select your shell\n")
    )?;

    if let Some(d) = detected {
        execute!(
            stdout,
            SetForegroundColor(Color::DarkGrey),
            Print(format!("  (detected: {})\n", d.name())),
            ResetColor
        )?;
    }
    println!();

    run_menu(stdout, &shells, initial, |shell| {
        if Some(*shell) == detected {
            format!("{} (detected)", shell.name())
        } else {
            shell.name().to_owned()
        }
    })
}

fn select_daemon_startup(stdout: &mut io::Stdout) -> Result<DaemonStartup> {
    let options = [
        DaemonStartup::OnShellInit,
        DaemonStartup::OnDemand,
        DaemonStartup::Systemd,
        DaemonStartup::Manual,
    ];

    execute!(
        stdout,
        SetForegroundColor(Color::Cyan),
        Print("Step 2/5: "),
        ResetColor,
        Print("When should the daemon start?\n")
    )?;
    execute!(
        stdout,
        SetForegroundColor(Color::DarkGrey),
        Print("  (daemon enables 22x faster searches via in-memory index)\n"),
        ResetColor
    )?;
    println!();

    run_menu(stdout, &options, 0, |opt| opt.name().to_owned())
}

fn select_build_config(stdout: &mut io::Stdout) -> Result<Option<BuildRecommendation>> {
    let sysinfo = SystemInfo::detect()?;
    let recommendation = sysinfo.recommend();

    execute!(
        stdout,
        SetForegroundColor(Color::Cyan),
        Print("Step 4/5: "),
        ResetColor,
        Print("Build Performance Settings\n")
    )?;
    execute!(
        stdout,
        SetForegroundColor(Color::DarkGrey),
        Print(format!(
            "  (detected: {} cores, {:.0}GB RAM)\n",
            sysinfo.cpu_cores, sysinfo.ram_gb
        )),
        ResetColor
    )?;
    println!();

    // Show detected tools
    let tools_status = format!(
        "  Tools: ccache {} | sccache {} | distcc {}",
        if sysinfo.ccache_available {
            "✓"
        } else {
            "✗"
        },
        if sysinfo.sccache_available {
            "✓"
        } else {
            "✗"
        },
        if sysinfo.distcc_available {
            "✓"
        } else {
            "✗"
        }
    );
    execute!(
        stdout,
        SetForegroundColor(Color::DarkGrey),
        Print(format!("{tools_status}\n")),
        ResetColor
    )?;
    println!();

    // Show recommendations
    println!("  Recommended settings:");
    for explanation in &recommendation.explanation {
        execute!(
            stdout,
            Print("    "),
            SetForegroundColor(Color::Green),
            Print("•"),
            ResetColor,
            Print(format!(" {explanation}\n"))
        )?;
    }
    println!();

    // Confirm
    let applies = select_binary_menu(stdout, "Apply recommended settings", "Skip (use defaults)")?;

    Ok(select_build_recommendation(recommendation, applies))
}

fn select_build_recommendation(
    recommendation: BuildRecommendation,
    applies: bool,
) -> Option<BuildRecommendation> {
    applies.then_some(recommendation)
}

fn apply_build_config(stdout: &mut io::Stdout, config: &BuildRecommendation) -> Result<()> {
    execute!(
        stdout,
        Print("  "),
        SetForegroundColor(Color::Blue),
        Print("→"),
        ResetColor,
        Print(" Applying build settings...")
    )?;

    let _write_lock = Settings::write_lock()?;
    let mut settings = Settings::load().context("Failed to load OMG settings")?;

    if !config.makeflags.is_empty() {
        settings.aur.makeflags = Some(config.makeflags.clone());
    }
    settings.aur.enable_ccache = config.enable_ccache;
    settings.aur.enable_sccache = config.enable_sccache;
    settings.aur.secure_makepkg = !config.disable_secure_makepkg;
    settings.aur.build_concurrency = config.build_concurrency;

    if let Err(e) = settings.save() {
        execute!(
            stdout,
            SetForegroundColor(Color::Yellow),
            Print(format!(" (failed: {e})\n")),
            ResetColor
        )?;
    } else {
        execute!(
            stdout,
            SetForegroundColor(Color::Green),
            Print(" ✓\n"),
            ResetColor
        )?;
    }

    Ok(())
}

fn confirm_env_capture(stdout: &mut io::Stdout) -> Result<bool> {
    execute!(
        stdout,
        SetForegroundColor(Color::Cyan),
        Print("Step 5/5: "),
        ResetColor,
        Print("Capture initial environment to omg.lock?\n")
    )?;
    execute!(
        stdout,
        SetForegroundColor(Color::DarkGrey),
        Print("  (enables team sync and drift detection)\n"),
        ResetColor
    )?;
    println!();

    select_binary_menu(
        stdout,
        "Yes, capture my environment",
        "No, I'll do it later",
    )
}

/// Run a two-option raw-mode menu; returns `true` when the first option is
/// chosen.
fn select_binary_menu(
    stdout: &mut io::Stdout,
    first_label: &str,
    second_label: &str,
) -> Result<bool> {
    let labels = [first_label, second_label];
    run_menu(stdout, &[true, false], 0, |chosen| {
        labels[usize::from(!chosen)].to_owned()
    })
}

fn read_optional_shell_rc(path: &str) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(content) => Ok(Some(content)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("Failed to read {path}")),
    }
}

/// Expand the leading `~` of a shell config path using `$HOME`.
fn resolve_config_path(shell: Shell) -> Result<PathBuf> {
    let home =
        std::env::var("HOME").context("Cannot locate your shell config: $HOME is not set")?;
    // Replace only the leading `~`; `replace` with no count would also mangle
    // any literal tilde later in the path.
    Ok(PathBuf::from(shell.config_file().replacen('~', &home, 1)))
}

/// Best-effort detection of the user's login shell from `$SHELL`.
pub(crate) fn shell_from_env() -> Option<Shell> {
    parse_shell_path(&std::env::var("SHELL").ok()?)
}

/// Whether `shell`'s rc file already contains the OMG hook line.
///
/// Used by `omg init` for idempotent installs and by `omg doctor` to verify
/// the hook actually landed on disk.
pub(crate) fn shell_rc_has_hook(shell: Shell) -> bool {
    resolve_config_path(shell)
        .ok()
        .and_then(|path| read_optional_shell_rc(&path.to_string_lossy()).ok())
        .flatten()
        .is_some_and(|content| content.contains("omg hook"))
}

fn ensure_shell_config_parent(config_path: &Path) -> Result<()> {
    let parent = config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("Shell configuration path has no parent directory")?;
    std::fs::create_dir_all(parent).with_context(|| {
        format!(
            "Failed to create shell config directory {}",
            parent.display()
        )
    })
}

// Let the launcher check this user's socket and ping the daemon. A process-name
// check can match another user's daemon or a process that is not serving IPC.
const DAEMON_SHELL_START: &str = "omg daemon >/dev/null 2>&1 &";

fn install_shell_hook(stdout: &mut io::Stdout, shell: Shell, start_daemon: bool) -> Result<()> {
    let config_path = resolve_config_path(shell)?;
    let hook_cmd = shell.hook_command();

    write!(stdout, "  ")?;
    write_styled(stdout, Color::Blue, "→")?;
    write!(stdout, " Installing {} hook...", shell.name())?;

    if let Some(content) = read_optional_shell_rc(&config_path.to_string_lossy())?
        && content.contains("omg hook")
    {
        writeln!(stdout, " (already installed)")?;
        return Ok(());
    }

    // Append hook to config
    ensure_shell_config_parent(&config_path)?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&config_path)
        .with_context(|| format!("Failed to open {}", config_path.display()))?;

    writeln!(file, "\n# OMG shell integration")?;

    // Optionally start daemon on shell init (background, silent)
    if start_daemon {
        writeln!(
            file,
            "# Start OMG daemon if not running (for 22x faster searches)"
        )?;
        writeln!(file, "{DAEMON_SHELL_START}")?;
    }

    writeln!(file, "{hook_cmd}")?;

    write!(stdout, " ")?;
    write_styled(stdout, Color::Green, "✓")?;
    writeln!(stdout)?;

    Ok(())
}

fn configure_daemon_startup(stdout: &mut io::Stdout, startup: DaemonStartup) -> Result<()> {
    write!(stdout, "  ")?;
    write_styled(stdout, Color::Blue, "→")?;
    write!(stdout, " Configuring daemon...")?;

    match startup {
        DaemonStartup::OnShellInit => {
            write!(stdout, " ")?;
            write_styled(stdout, Color::Green, "✓")?;
            writeln!(stdout, " (via shell hook)")?;
        }
        DaemonStartup::OnDemand => match start_on_demand_daemon() {
            Ok(()) => {
                write!(stdout, " ")?;
                write_styled(stdout, Color::Green, "✓")?;
                writeln!(stdout, " (started)")?;
            }
            Err(error) => writeln!(stdout, " (not started: {error}; continuing setup)")?,
        },
        DaemonStartup::Systemd => {
            create_systemd_service()?;
            write!(stdout, " ")?;
            write_styled(stdout, Color::Green, "✓")?;
            writeln!(stdout, " (systemd service created)")?;
        }
        DaemonStartup::Manual => {
            writeln!(stdout, " (skipped - run 'omg daemon' when ready)")?;
        }
    }

    Ok(())
}

fn start_on_demand_daemon() -> Result<()> {
    let daemon = omgd_sibling_path().context("matching omgd binary was not found next to omg")?;
    Command::new(daemon)
        .arg("--")
        // Detach stdio: the daemon outlives this process, and an inherited
        // pipe would keep the parent's readers open forever.
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("Failed to start the OMG daemon")?;
    Ok(())
}

/// Resolve the `omgd` binary shipped next to the running `omg`, so a PATH
/// entry shadowing an older install cannot start a version-mismatched daemon
/// (same strategy as `commands::daemon`). Returns `None` when no sibling
/// binary exists.
fn omgd_sibling_path() -> Option<PathBuf> {
    crate::core::paths::sibling_binary("omgd")
}

fn systemd_quote_exec_path(path: &Path) -> String {
    let mut quoted = String::with_capacity(path.as_os_str().len() + 2);
    quoted.push('"');
    for character in path.to_string_lossy().chars() {
        match character {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '%' => quoted.push_str("%%"),
            '$' => quoted.push_str("$$"),
            _ => quoted.push(character),
        }
    }
    quoted.push('"');
    quoted
}

/// `omgd` already runs in the foreground (`Type=simple`); the removed
/// `--foreground` flag is rejected by the binary.
fn systemd_exec_start_line(omgd_path: Option<&Path>) -> String {
    omgd_path.map_or_else(
        || "ExecStart=%h/.local/bin/omgd".to_owned(),
        |path| format!("ExecStart={}", systemd_quote_exec_path(path)),
    )
}

fn create_systemd_service() -> Result<()> {
    let home = std::env::var("HOME")?;
    let service_dir = format!("{home}/.config/systemd/user");
    std::fs::create_dir_all(&service_dir)?;

    // Pin ExecStart to the omgd shipped next to this omg; fall back to the
    // historical %h/.local/bin location when it cannot be resolved.
    let exec_start = systemd_exec_start_line(omgd_sibling_path().as_deref());

    let service_content = format!(
        r"[Unit]
Description=OMG Package Manager Daemon
After=default.target

[Service]
Type=simple
{exec_start}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
"
    );

    std::fs::write(format!("{service_dir}/omgd.service"), service_content)?;

    let reload = Command::new("systemctl")
        .args(["--user", "daemon-reload", "--"])
        .status()
        .context("Failed to run systemctl --user daemon-reload")?;
    if !reload.success() {
        anyhow::bail!("systemctl --user daemon-reload failed with {reload}");
    }

    let enable = Command::new("systemctl")
        .args(["--user", "enable", "--now", "--", "omgd.service"])
        .status()
        .context("Failed to enable the omgd systemd user service")?;
    if !enable.success() {
        anyhow::bail!("systemctl --user enable --now omgd.service failed with {enable}");
    }

    Ok(())
}

async fn capture_environment(stdout: &mut io::Stdout) -> Result<()> {
    write!(stdout, "  ")?;
    write_styled(stdout, Color::Blue, "→")?;
    write!(stdout, " Capturing environment...")?;
    stdout.flush()?;

    // Use the existing env capture function
    match crate::core::env::fingerprint::EnvironmentState::capture().await {
        Ok(state) => {
            if let Err(e) = state.save("omg.lock") {
                writeln!(stdout, " (failed: {e})")?;
            } else {
                write!(stdout, " ")?;
                write_styled(stdout, Color::Green, "✓")?;
                writeln!(stdout)?;
            }
        }
        Err(e) => {
            writeln!(stdout, " (skipped: {e})")?;
        }
    }

    Ok(())
}

fn print_completion(stdout: &mut io::Stdout, state: &WizardState) -> Result<()> {
    println!();
    execute!(
        stdout,
        SetForegroundColor(Color::Green),
        Print("═══════════════════════════════════════════════════════════\n"),
        Print("  ✓ Setup Complete!\n"),
        Print("═══════════════════════════════════════════════════════════\n"),
        ResetColor
    )?;
    println!();

    println!(
        "  {} Restart your shell or run:",
        crate::cli::style::emphasis("Next:")
    );
    if let Some(shell) = state.shell {
        println!("      source {}", shell.config_file());
    }
    println!();

    println!(
        "  {} Try these commands:",
        crate::cli::style::emphasis("Quick start:")
    );
    println!("      omg search vim          # 22x faster than pacman");
    println!("      omg use node 20         # Install & switch Node.js");
    println!("      omg status              # System overview");
    println!("      omg dash                # Interactive dashboard");
    println!();

    execute!(
        stdout,
        SetForegroundColor(Color::DarkGrey),
        Print("  Full docs: https://github.com/PyRo1121/omg/tree/main/docs\n"),
        ResetColor
    )?;

    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn raw_mode_menu_recognizes_interrupt_keys() {
        for code in [KeyCode::Char('c'), KeyCode::Char('d')] {
            let key = KeyEvent::new(code, KeyModifiers::CONTROL);
            assert!(is_menu_cancel_key(&key));
        }
        assert!(is_menu_cancel_key(&KeyEvent::new(
            KeyCode::Char('q'),
            KeyModifiers::NONE
        )));
        assert!(!is_menu_cancel_key(&KeyEvent::new(
            KeyCode::Char('c'),
            KeyModifiers::NONE
        )));
    }

    #[test]
    fn systemd_exec_paths_are_quoted_and_escape_unit_expansion() {
        let path = Path::new(r#"/opt/OMG $Build%/omg\"daemon"#);
        assert_eq!(
            systemd_quote_exec_path(path),
            r#""/opt/OMG $$Build%%/omg\\\"daemon""#
        );
    }

    #[test]
    fn systemd_exec_start_omits_removed_foreground_flag() {
        assert_eq!(
            systemd_exec_start_line(None),
            "ExecStart=%h/.local/bin/omgd"
        );
        let path = Path::new("/opt/omg/omgd");
        let line = systemd_exec_start_line(Some(path));
        assert_eq!(line, format!("ExecStart={}", systemd_quote_exec_path(path)));
        assert!(!systemd_exec_start_line(None).contains("--foreground"));
        assert!(!line.contains("--foreground"));
    }

    #[test]
    fn disabled_daemon_forces_manual_wizard_startup() {
        assert_eq!(
            effective_daemon_startup(DaemonStartup::OnShellInit, true),
            DaemonStartup::Manual
        );
        assert_eq!(
            effective_daemon_startup(DaemonStartup::OnDemand, false),
            DaemonStartup::OnDemand
        );
    }

    #[test]
    fn skipping_build_recommendations_preserves_existing_settings() {
        let recommendation = BuildRecommendation {
            makeflags: "-j8".to_string(),
            enable_ccache: true,
            enable_sccache: false,
            disable_secure_makepkg: false,
            build_concurrency: 8,
            explanation: Vec::new(),
        };

        assert!(select_build_recommendation(recommendation.clone(), false).is_none());
        assert_eq!(
            select_build_recommendation(recommendation, true)
                .expect("apply selection")
                .build_concurrency,
            8
        );
    }

    #[test]
    fn shell_hook_parent_directory_is_created_before_opening_rc_file() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join(".config/fish/config.fish");

        ensure_shell_config_parent(&config_path).unwrap();

        assert!(config_path.parent().unwrap().is_dir());
    }

    #[test]
    fn test_read_optional_shell_rc_missing_is_none() {
        let missing = tempfile::TempDir::new()
            .unwrap()
            .path()
            .join("does-not-exist");
        assert!(
            read_optional_shell_rc(missing.to_str().unwrap())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_read_optional_shell_rc_reads_content() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(".zshrc");
        std::fs::write(&path, "eval \"$(omg hook zsh)\"\n").unwrap();
        let content = read_optional_shell_rc(path.to_str().unwrap())
            .unwrap()
            .unwrap();
        assert!(content.contains("omg hook"));
    }

    #[test]
    fn test_read_optional_shell_rc_unreadable_errors() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(".zshrc");
        std::fs::write(&path, "eval \"$(omg hook zsh)\"\n").unwrap();
        let original = std::fs::metadata(&path).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
        let blocked = std::fs::read_to_string(&path).is_err();
        let result = read_optional_shell_rc(path.to_str().unwrap());
        let _ = std::fs::set_permissions(&path, original);
        if !blocked {
            return;
        }
        assert!(
            result.is_err(),
            "unreadable shell rc must fail closed, got {result:?}"
        );
    }
}
