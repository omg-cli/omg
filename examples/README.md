# OMG configuration examples

These files are starting points. Read and edit a copy before using it. The [configuration guide](../docs/configuration.md) lists the accepted settings and defaults.

| File | Copy to | What it controls |
| --- | --- | --- |
| [`config.toml`](./config.toml) | The path printed by `omg config path` | Local OMG settings such as telemetry and AUR builds |
| [`policy.toml`](./policy.toml) | The policy path described in the [security guide](../docs/security.md#security-policy) | Local security policy |
| [`.tool-versions`](./.tool-versions) | Your project root | Runtime version requests for that project |

## Before copying a file

Run `omg config path` to find the settings file on this machine. Review `config.toml` before replacing an existing file. Review policy changes with whoever owns the policy; an example is not an approved organization policy.

For a new project, copy `.tool-versions` into its root, edit the example versions, and commit the reviewed file. `omg use node` can detect the Node pin there. The shell hook can select an already installed version when you enter the project. The file does not install runtimes, write `omg.lock`, or guarantee identical dependencies.

## Check your changes

```bash
omg config validate
```

```bash
omg audit policy
```

```bash
omg which node
```

If the commands report an error, keep the original file and use [troubleshooting](../docs/troubleshooting.md) to diagnose it.

## Where to go next

- [Runtime management](../docs/runtimes.md) explains version files and installation.
- [Team environments](../docs/team.md) explains the separate `omg.lock` record.
- [AUR support](../docs/aur.md) explains build settings and their limits.
