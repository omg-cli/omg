# Built-in update notices

**In plain words:** How OMG tells you that a newer version exists, when it checks, and how to silence the notice.

> New to the terminal? Read [Getting started](./getting-started.md) and keep
> [the glossary](./glossary.md) open while you work.

After a successful interactive OMG command, OMG checks its local update cache
and can advise you to run `omg self-update`. Shell integration is not required.
Existing `omg hook bash`, `omg hook zsh`, and `omg hook fish` integrations can
also display the same notice when an interactive terminal opens.

The first eligible command or terminal starts a background check; a subsequent
invocation can show:

```text
OMG 0.1.223 is available (installed: 0.1.222). Update with your package manager or `omg self-update`. Notes: https://github.com/omg-cli/omg/releases/tag/v0.1.223
```

Checks and notices are limited to once per day per user cache, including failed
network attempts. The foreground only reads local state; a separate process has at most
three seconds to fetch the same HTTPS release marker used by `omg self-update`.
Offline errors are silent. The check sends no install identifier or telemetry,
although the HTTPS server receives normal request/network metadata.
Piped output, quiet/JSON commands, help/completion protocols, `self-update`,
CI and root sessions do not trigger command notices. Failed commands do not
display an update notice or change their exit status.
Versions older than the installed build, prereleases and malformed metadata are
not advertised. Cached results older than seven days are not shown.

No packages are installed automatically. Package-managed installations should
update through their package manager. Direct installations can use
`omg self-update`, which retains checksum and provenance verification.

To disable both checking and notices, export this in your shell configuration
(before the OMG hook, if installed):

```bash
# Bash or Zsh
export OMG_NO_UPDATE_CHECK=1
```

```fish
# Fish
set -gx OMG_NO_UPDATE_CHECK 1
```

Remove that variable to enable the feature again. State lives in
`$XDG_CACHE_HOME/omg/update-notice.json` (normally `~/.cache/omg`), or the explicitly
configured `OMG_CACHE_DIR`. Unsafe or unreadable state is ignored. A damaged cache
can be removed to let the next eligible command or terminal recreate it; it is
not required to use OMG.
