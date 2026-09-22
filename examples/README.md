# OMG Configuration Examples

This directory provides starter templates for configuring OMG and locking project runtime versions.

## Available Templates

| File | Target Location | Description |
| :--- | :--- | :--- |
| [`config.toml`](config.toml) | `~/.config/omg/config.toml` | Main configuration template with annotated settings for AUR builds, telemetry, and cache controls. |
| [`policy.toml`](policy.toml) | `~/.config/omg/policy.toml` | Security policy template for defining minimum trust grades, allowed licenses, and package restrictions. |
| [`.tool-versions`](.tool-versions) | `<project-root>/.tool-versions` | Standard version-locking file for pinning Node, Python, Go, Rust, and other project runtimes. |

## Quick Start

Copy the templates to your user configuration directory:

```bash
mkdir -p ~/.config/omg
cp examples/config.toml ~/.config/omg/
cp examples/policy.toml ~/.config/omg/
```

Verify your active configuration:

```bash
omg config list
omg config validate
omg audit policy
```

## Authoritative Documentation

For complete reference manuals, available settings, security boundaries, and migration guides, see the official documentation:

- **[Configuration Guide](../docs/configuration.md)** — All valid settings, defaults, environment overrides, and limits
- **[Security Policy Guide](../docs/security.md#security-policy)** — Policy grades, enforcement rules, and audit verification
- **[Runtime Management](../docs/runtimes.md)** — Version pinning, switching, and `.tool-versions` compatibility
- **[AUR Support](../docs/aur.md)** — Build concurrency, sandbox options, and review mechanisms
