# OMG Configuration Examples

This directory contains example configuration files to help you get started with OMG.

---

## Quick Start

1. **Copy templates to your config directory:**
   ```bash
   mkdir -p ~/.config/omg
   cp examples/config.toml ~/.config/omg/
   cp examples/policy.toml ~/.config/omg/
   ```

2. **Customize for your needs:**
   - Edit `~/.config/omg/config.toml` for general settings
   - Edit `~/.config/omg/policy.toml` for security policies
   - Copy `examples/.tool-versions` to your project root for runtime locking

3. **Verify configuration:**
   ```bash
   omg config get
   omg audit policy
   ```

---

## Available Templates

### config.toml

**Purpose:** Main OMG configuration file  
**Location:** `~/.config/omg/config.toml`  
**Contents:**
- General settings (daemon, shell, telemetry)
- AUR build configuration (concurrency, caching, security)
- Runtime backend selection

**Use Cases:**
- Performance tuning (parallel builds, caching)
- Security hardening (sandboxed builds, reviews)
- Team environments (shared caches, reproducible builds)

**Documentation:** See inline comments in the file

### policy.toml

**Purpose:** Security policy enforcement  
**Location:** `~/.config/omg/policy.toml`  
**Contents:**
- Security grading requirements (Locked/Verified/Community/Risk)
- AUR package restrictions
- License restrictions
- Package bans

**Use Cases:**
- Enterprise security requirements
- Compliance enforcement (SOC2, ISO27001)
- Team security standards
- Personal safety guardrails

**Documentation:** See inline comments in the file

### .tool-versions

**Purpose:** Project runtime version locking  
**Location:** `<project-root>/.tool-versions` (checked into git)  
**Contents:**
- Locked versions for Node.js, Python, Rust, Go, Ruby, Java, etc.
- Compatible with mise, asdf, and other version managers

**Use Cases:**
- Team environment synchronization
- Reproducible builds
- CI/CD version consistency
- Preventing "works on my machine" issues

**Documentation:** See inline comments in the file

---

## Configuration Presets

### Performance-Optimized

**Goal:** Maximum build speed

**config.toml:**
```toml
[aur]
build_method = "native"
build_concurrency = 8
cache_builds = true
enable_ccache = true
enable_sccache = true
```

**When to use:**
- Development machines with fast CPUs
- Frequent rebuilds of same packages
- Local development (not CI)

### Security-Hardened

**Goal:** Maximum security

**config.toml:**
```toml
[aur]
build_method = "bubblewrap"
review_pkgbuild = true
secure_makepkg = true
allow_unsafe_builds = false
```

**policy.toml:**
```toml
minimum_grade = "Locked"
allow_aur = false
require_pgp = true
```

**When to use:**
- Production servers
- Enterprise environments
- Security-critical systems

### Team/CI Environment

**Goal:** Reproducibility

**config.toml:**
```toml
telemetry_enabled = false

[aur]
build_method = "chroot"
pkgdest = "/opt/omg/packages"
srcdest = "/opt/omg/sources"
cache_builds = true
```

**When to use:**
- CI/CD pipelines
- Shared build environments
- Team development servers

---

## Common Configurations

### Disable Telemetry

```toml
# config.toml
telemetry_enabled = false
```

Or use environment variable:
```bash
export OMG_TELEMETRY=0
```

### Shell Hook Integration

Add the hook to your shell configuration (`~/.bashrc`, `~/.zshrc`, etc.):
```bash
eval "$(omg hook bash)"
```

### Restrict to Official Packages Only

```toml
# policy.toml
allow_aur = false
minimum_grade = "Verified"
```

### Limit Allowed Licenses

```toml
# policy.toml
allowed_licenses = ["MIT", "Apache-2.0", "BSD-3-Clause"]
```

---

## Tips & Best Practices

### For Individuals

1. **Start with defaults** - Only customize what you need
2. **Enable caching** - `cache_builds = true` saves rebuild time
3. **Use native build method** - Fastest for trusted packages
4. **Review AUR packages** - Enable `review_pkgbuild` for untrusted sources

### For Teams

1. **Lock runtime versions** - Use `.tool-versions` in project root
2. **Share configuration** - Commit `config.toml` template to repo
3. **Enforce policies** - Use `policy.toml` for security standards
4. **Centralize caches** - Set `pkgdest` and `srcdest` to shared locations

### For CI/CD

1. **Disable telemetry** - `telemetry_enabled = false`
2. **Use chroot builds** - `build_method = "chroot"` for isolation
3. **Cache dependencies** - Persist `~/.local/share/omg` between runs
4. **Lock everything** - Pin exact versions in `.tool-versions`

---

## Validation

### Check Configuration

```bash
# Show current config
omg config get

# Show specific value
omg config get aur.build_concurrency

# Test configuration syntax
omg config validate
```

### Check Policy

```bash
# Show current policy
omg enterprise policy show

# Preview whether a package install would proceed
omg install --dry-run firefox
```

### Verify Runtime Versions

```bash
# Show active versions
omg list

# Check against .tool-versions
omg env check
```

---

## Troubleshooting

### Configuration Not Loaded

**Symptom:** Changes to `config.toml` don't take effect

**Solutions:**
1. Check file location: `~/.config/omg/config.toml`
2. Verify TOML syntax: `omg config validate`
3. Restart daemon: `pkill omgd && omg daemon`

### Policy Blocking Installations

**Symptom:** `omg install` fails with policy error

**Solutions:**
1. Check enterprise policy: `omg enterprise policy show`
2. Preview the install: `omg install --dry-run <package>`
3. Adjust enterprise policy in the dashboard, or the local host file with `omg audit policy`

### Runtime Versions Not Switching

**Symptom:** `omg use node 20` doesn't change version

**Solutions:**
1. Check shell hook: `eval "$(omg hook bash)"`
2. Reload shell: `exec $SHELL`
3. Verify installation: `omg list node`

---

## Related Documentation

- **[Configuration Guide](../docs/configuration.md)** - Complete config reference
- **[Security Guide](../docs/security.md)** - Security features and policies
- **[Runtime Management](../docs/runtimes.md)** - Version management guide
- **[Performance Tips](../docs/performance-tips.md)** - Optimization strategies

---

## Contributing

Found a useful configuration pattern? Share it!

1. Add your example to this directory
2. Document the use case
3. Submit a PR to `https://github.com/omg-cli/omg`

See [CONTRIBUTING.md](../CONTRIBUTING.md) for details.
