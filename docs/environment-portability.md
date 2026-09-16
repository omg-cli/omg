# Portable environment planning

`omg env plan --target ubuntu-x86_64` reads the current directory's `.omg.toml`
and prints a JSON preview. It does not install tools, execute scripts, copy
dotfiles, contact registries, or change `omg.lock`.

```toml
[environment]
schema_version = 1
tools = ["git", "compiler"]

[environment.runtimes]
node = "22"

[environment.packages.ubuntu-x86_64]
git = "git"
compiler = "build-essential"

[environment.packages.arch-x86_64]
git = "git"
compiler = "base-devel"

[environment.dotfiles]
"dotfiles/editor.toml" = ".config/editor/config.toml"
```

Targets: `arch-x86_64`, `debian-x86_64`, `ubuntu-x86_64`, `fedora-x86_64`,
and `macos-aarch64`. Target selection is explicit; it does not need to match
the machine generating the preview. Existing `[scripts]` configuration can coexist.

Every requested tool needs an explicit native package mapping for the selected
target. Missing mappings appear in `unmapped_tools`; OMG never guesses an
equivalent package. Exit success means the manifest is valid, not that every
tool is mapped or installable. Runtime requirements remain uninterpreted intent.
Package names in this initial schema accept letters, digits, dots, underscores,
pluses and hyphens, starting with a letter or digit.

Dotfile sources are relative to the manifest directory; destinations are relative
to the user's home. Paths are validated lexically only. No file contents are read,
and existence, symlinks, ownership, conflicts and permissions are not checked by
this preview. Do not include credentials or employer-private data in shared files.

This is the first portability increment. Cross-platform resolution, reviewed
application, dotfile backups and an expanded lock schema remain unimplemented.
Existing `omg env capture`, `check`, `share` and `sync` retain their existing
behavior. A captured lockfile is not yet a portable installation recipe.
