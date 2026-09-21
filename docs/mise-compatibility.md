# mise compatibility in OMG

**In plain words:** If your project already uses mise, this page lists the parts OMG understands and the parts it does not.

> New to the terminal? Read [Getting started](./getting-started.md) and keep
> [the glossary](./glossary.md) open while you work.

This is an implementation inventory and acceptance plan, not a claim of full compatibility. It follows the request to expand OMG's existing native mise support while retaining OMG's installation controls.

## Reference and evidence

- Upstream baseline: [mise v2026.9.7](https://github.com/jdx/mise/releases/tag/v2026.9.7), source [0db3fbe9efcee1944bc4990434c1a5ebcb480fca](https://github.com/jdx/mise/tree/0db3fbe9efcee1944bc4990434c1a5ebcb480fca). The annotated tag was resolved through GitHub, rather than treating the tag-object SHA as the source revision.
- OMG inspected revision: [0de93ce6](https://github.com/omg-cli/omg/tree/0de93ce6). Inspection date: September 13, 2026. The repository has since moved to `omg-cli/omg`. Layered mise pins, project environments, and task dependencies described below are current CLI behavior. This page remains an inventory of what that support includes and what it does not.
- Existing implementation tests cited below were read, not rerun during this inventory. They are not yet differential tests against the pinned mise binary.
- Live upstream documentation is useful for discovery. Conformance fixtures must use the pinned source and release because documentation can advance independently.

There are two different completion targets: running existing mise projects through OMG, and replacing every mise command, plugin interface, and system-management feature. The first is the proposed initial scope. Completing it must not be advertised as the second.

## Configuration-layer increment

The environment resolver now reads project-local overrides, comma-separated `MISE_ENV` selections, selected-environment local overrides, grouped project configurations, and sorted `conf.d` fragments. Child project configurations override parent configurations. Each document retains its declaring configuration root for relative directives, and configuration discovery uses bounded regular-file reads without executing project code.

The portable harness compiles the production modules directly: `cargo test --manifest-path tests/mise-compat/Cargo.toml`. Its 29 tests passed on Windows on September 14, 2026. The compatibility cases also run in the normal crate test suite. Hosted Linux and QEMU validation is tracked by the implementation PR; the Windows result alone is not Linux execution evidence.

The follow-up project-workflow increment also feeds runtime pins and task discovery through the shared loader. Global/system configuration, complete upstream template semantics, and backend/plugin parity remain outstanding. No full mise compatibility percentage is claimed.

### Native project workflows

Runtime pins now consume local, selected-environment, grouped, and fragment configurations. Later mise layers replace earlier pins after native alias normalization (`nodejs` → `node`, for example). Dedicated version files still win within the same directory; the nearest directory wins across ancestors. A malformed ancestor mise configuration is reported and skipped during hook pin discovery, while malformed current-directory configuration fails. Hook discovery never reads environment files or executes source scripts.

Tasks use the same ordered project documents, including ancestor tasks. OMG supports shorthand string tasks, string/array `run`, plain-name `depends`, dependency-only tasks, task environments, and literal task directories. The complete dependency graph is validated before execution: missing dependencies and cycles fail before any task starts. Shared dependencies run once, sequentially in declared dependency order; failure stops the remaining plan. Additional command-line arguments go only to the requested task, and task-local environment values do not flow into its dependencies.

Tasks default to their declaring config root; a relative `dir` resolves from that root. Runtime selection and project environment layers use the invocation project, while each task's environment templates use its declaring root. No process-global directory change is needed. These semantics follow the pinned [task configuration reference](https://github.com/jdx/mise/blob/0db3fbe9efcee1944bc4990434c1a5ebcb480fca/docs/tasks/task-configuration.md), with sequential execution as an explicit OMG limitation.

Unsupported execution-affecting task properties and `task_config` now produce an error during task discovery instead of being ignored. This includes post-dependencies, conditional execution, custom shells, sandbox controls, file tasks, dependency arguments/objects/patterns, and run/directory templates. Description and hide metadata are accepted; task-list visibility is not yet matched to mise. Namespaced dependencies can reference a declared task, but the existing OMG CLI task-name rules still limit directly requested names. The portable harness now has 37 passing tests; new actual-process regressions require the hosted Unix suite and are not covered by that Windows result.

## Migrating existing OMG projects

Within each directory, ordinary configuration and local overrides load first. Each `MISE_ENV` selection then loads its ordinary files followed by its local files, before the next selection. This follows the pinned upstream [`LOCAL_CONFIG_FILENAMES` and `DEFAULT_CONFIG_FILENAMES` ordering](https://github.com/jdx/mise/blob/0db3fbe9efcee1944bc4990434c1a5ebcb480fca/src/config/mod.rs). Grouped `config*.toml` files use the project root for relative directives; the legacy `.config/mise/mise.toml` and `.config/mise/mise.local.toml` aliases use their containing directory, matching upstream [`config_root`](https://github.com/jdx/mise/blob/0db3fbe9efcee1944bc4990434c1a5ebcb480fca/src/config/config_file/config_root.rs).

Applying previously ignored environment layers is an intentional behavior change for explicit `omg run` and task execution. Existing local files or a pre-existing `MISE_ENV` selection can change assignments, PATH additions, required-value validation, and explicitly sourced scripts after upgrading. This support does not require a new opt-in flag.

Before upgrading:

1. Review project and ancestor `mise.local.toml`, `.mise.local.toml`, selected-environment files, and grouped `.config/mise`, `.mise`, and `mise` configurations. Projects beneath your home directory can inherit its grouped configuration too; this is ancestor discovery, not an independent global/system configuration search.
2. Check `MISE_ENV` in the invoking environment. Comma-separated selections are processed in order, with the final duplicate retained. Names accept ASCII letters, digits, underscores, and hyphens; other characters now cause an error. Unset `MISE_ENV` for commands that must not select named layers. That does not disable ordinary local overrides or fragments.
3. Move environment directives you do not want OMG to consume out of the discovered configuration layers. Keep intended shared assignments in the desired project configuration and check child/local precedence. There is no compatibility switch that restores the former two-file-only environment resolver.
4. Validate a benign explicit command in the project before running tasks with side effects. Review `_.source` directives first: discovery does not execute them, but explicit command/task environment resolution can.

Automatic shell hooks continue selecting installed runtimes without importing project environment directives. The project-workflow increment also applies the additional layers to pins and task discovery. Review local/selected pins and ancestor tasks before upgrading: previously ignored pins can select a different runtime, dependencies now execute before their parent, and unsupported task controls now fail visibly. Tasks found from a subdirectory run from their declaring root by default. The release notes classify this migration as a breaking behavior change; the implementation branch does not itself publish or replace a tagged release.

## Baseline native project support (before this increment)

| Area | Evidence in OMG | Remaining compatibility work |
| --- | --- | --- |
| Basic tool pins | `src/hooks/mod.rs::parse_mise_toml_file` reads plain strings and inline `version` values. | Version arrays, backend options, aliases, and backend-qualified names need an explicit model instead of the current single-string map. |
| Config file discovery | Hook detection and `src/config/mise_env.rs::chain_files` search ancestor `mise.toml` and `.mise.toml` files. | Shared discovery must cover local overrides, selected environments, global/system config, fragments, and documented precedence. |
| Task discovery scope | `TaskDetector::detect_mise_tasks` reads the current directory's two config filenames. | Ancestor tasks and selected config layers must use the same discovery result as tools and environments. |
| TOML task commands | String and string-array `run` values become sequential shell commands. Existing tests cover detection, first argument handling, and stopping after failure. | Shorthand tasks and validation of every run-array member; do not silently discard invalid values. |
| Task dependencies | Current `Task` stores name, command, arguments, source, and ecosystem. | Dependency-only tasks, `depends`, ordering rules, deduplication, cycles, and failure propagation require a task graph. |
| Task properties | Current adapter extracts `run` and environment settings. | Track each documented task property, including working directory, shell, aliases, arguments, conditions, sources/outputs, templates, and concurrency. Unsupported execution-affecting properties must not disappear silently. |
| File tasks | No mise file-task discovery in the inspected task adapter. | File-task roots, executable rules, interpreter selection, metadata, namespaces, and argument handling. |
| Basic environment values | `src/config/mise_env.rs` implements strings/integers, unsets, defaults, required values, redaction metadata, and before/after-tools resolution. | Compare ordering and merge semantics against upstream fixtures; parsing support alone is not conformance. |
| Environment files | Explicit run/task execution accepts dotenv, JSON, and TOML through a bounded regular-file reader. | YAML, glob/option semantics, path resolution across config layers, and provider-specific directives. |
| Environment templates | Supported expressions include `env.NAME` and `config_root`; other template expressions fail. | `[vars]`, documented functions and filters, and full template behavior need a defined evaluator and trust policy. |
| Environment source scripts | Explicit tasks can evaluate source scripts; automatic hooks never import project environment directives. | Preserve the automatic-hook boundary and track it as an intentional policy difference from mise shell activation. |
| Named config environments | `chain_files` only enumerates the two ordinary project filenames. | `MISE_ENV`, selection flags, environment-local files, hierarchy order, and interactions with local overrides. |
| Runtime providers | OMG has native runtime managers and a curated GitHub-release tool registry. | A native manager with a similar tool name is not proof of identical mise backend semantics, options, or artifact selection. |
| Backend-qualified tools | `parse_mise_toml_file` currently skips names containing `:`. | Preserve backend identity and version/options, map supported operations into OMG's controlled installers, and report unsupported providers. |
| Lockfile compatibility | No mise lockfile integration is established by the inspected configuration/task paths. | `mise.lock` parsing, platform selection, checksums, refresh behavior, and locked/offline failure rules need their own implementation and tests. |
| Installed tools and PATH | OMG selects its own installations; existing shell hooks validate runtime bin directories. | Migration/reuse of mise installations, version precedence, multiple versions, shell restoration, and shims require separate contracts. |
| Plugins and secret providers | Native support is not established for the external mise plugin interfaces or encrypted-secret providers. | Assess each pinned plugin interface and provider; do not mark delegation or a skipped provider as native coverage. |
| CLI compatibility | OMG uses its own command surface; `removed_cli_flags_stay_rejected` rejects `--runtime-backend native-then-mise`. | Define command mappings for project workflows. Full CLI replacement is a separate target, including completion, help, diagnostics, and exit semantics. |

Implementation references: [hooks](../src/hooks/mod.rs), [environment parsing](../src/config/mise_env.rs), [task runner](../src/core/task_runner.rs), [tool registry](../src/runtimes/tool_registry.rs), and [CLI regression](../src/cli/args.rs).

## Proposed implementation order

1. **Conformance inventory and diagnostics.** Enumerate the pinned configuration/task keys and assign stable case IDs. Fixtures must expose silent omissions before expanding the supported surface. Report unsupported behavior with file, task/key, and reason before running the affected operation.
2. **One configuration resolver.** Resolve project/local/environment/global files once and share the result between tool selection, environment evaluation, and task discovery. Preserve the declaring path and precedence for every value.
3. **Task model and execution graph.** Represent dependencies and properties before rendering commands. Implement shorthand, dependency-only tasks, ordered steps, file tasks, aliases, working directories, arguments, cancellation, and error propagation in independently tested increments.
4. **Environment and template completion.** Add missing formats and directives with bounded parsing. Keep parsing separate from any script execution, network access, or secret retrieval. Test source order and redaction at observable outputs.
5. **Tool requests and lockfiles.** Preserve the backend, version list, options, platform, and expected integrity information. Route compatible requests through OMG's native managers and controlled managed-tool installers.
6. **Installation migration and shell behavior.** Test PATH selection and restoration alongside existing mise installations. Validate actual Omarchy configuration and named Omarchy images before making compatibility claims about that distro.
7. **Additional product surface.** If full mise replacement is chosen, add separate workstreams for plugin protocols, bootstrap/system management, remote execution, daemons, caches, generators, and remaining CLI commands. None is covered merely by completing the project parser.

## Measuring completion

Maintain case statuses as `not-tested`, `failing`, `passing`, or `policy-difference`. Each result must include the fixture ID, baseline version, OMG source SHA, platform, command, expected observation, actual observation, and retained output. A missing runner or skipped case is not a pass.

For a published parity percentage, the denominator is a committed, reviewed list of upstream behaviors in the chosen scope. Policy differences remain visible and do not count as identical behavior. A narrower compatible profile can be useful, but must name its scope. Full mise replacement requires all additional workstreams above and a review of the complete pinned CLI/schema surface; this inventory is not an exhaustive schema enumeration.

Differential cases should execute the same benign fixture with the pinned mise release and OMG, comparing task output, dependency ordering constraints, exit status, working directory, environment, PATH selection, and controlled filesystem effects. Normalize temporary roots and explicitly identified nondeterministic fields only. Do not compare just parser output or test only that a command exits zero.

Offline fixtures use local scripts and deterministic fake tools. Network/provider tests use explicit versions and isolated guest state. Test credentials are dummy values; fixture output must never include workstation secrets. Existing privilege, source verification, archive, and activation regression suites remain required alongside new compatibility cases.

Use the existing staged [QEMU workflow](qemu-local.md#dispatch-and-evidence) for Linux execution when the Windows workstation lacks Linux/KVM. First prove focused cases on a supported Linux runner, then include representative cases in the guest inventory. QEMU Arch results and Omarchy-specific results must remain distinguishable.

## Upstream feature references

- [Configuration and precedence](https://mise.jdx.dev/configuration.html)
- [Named configuration environments](https://mise.jdx.dev/configuration/environments.html)
- [Environment variables and directives](https://mise.jdx.dev/environments/)
- [Task overview](https://mise.jdx.dev/tasks/), [TOML tasks](https://mise.jdx.dev/tasks/toml-tasks.html), and [file tasks](https://mise.jdx.dev/tasks/file-tasks.html)
- [Task property reference](https://mise.jdx.dev/tasks/task-configuration.html)
- [Lockfiles](https://mise.jdx.dev/dev-tools/mise-lock.html)
- [Backends](https://mise.jdx.dev/dev-tools/backends/)
- [Trust and security](https://mise.jdx.dev/security.html)
- [Pinned upstream documentation tree](https://github.com/jdx/mise/tree/0db3fbe9efcee1944bc4990434c1a5ebcb480fca/docs)
