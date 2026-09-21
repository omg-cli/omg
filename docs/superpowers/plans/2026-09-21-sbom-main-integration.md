# Integrate the published SBOM verification slice

PR #445 merged as `5ed70bc4` after all hosted gates passed. Its QEMU binaries and harness used source `46998028`, verified as current main plus head `6ce81e18`; each Linux inventory recorded 178 passes and 3 declared skips. This does not establish the overall behavioral coverage target.

## Scope and ancestry

Reconcile the existing #447 head `74a5a48b` with that validated main. Preserve shared SBOM export, strict native advisory identities, configuration regressions, native assertion bindings, and detailed failure reporting. Preserve the later first-writer/runtime/daemon/QEMU work separately on `codex/verification-followups`; it is not discarded or silently folded into this PR.

The Fedora patch `1fc57ca4` from #440 and its port `a769689b` have the same stable patch ID `2ff66f12f5f72f76da73896b30fc67e86ae2d185`. Its Clippy correction is already present in #445. The original #440 commits are ancestors of #447, so a normal merge can retain their history. GitHub documents [indirect merges](https://docs.github.com/en/pull-requests/reference/pull-request-merges); verify the actual resulting PR state rather than assuming it.

Conflict review retained stricter advisory validation, duplicate dpkg-field rejection, complete SBOM refusal, historical inventory policies, and removal of the unused legacy system scanner. Every shared historical policy entry matched exactly; none was removed. Existing main's Python catalog, executable Python oracle and SLSA fixes remain present. Carry forward the already tested octal permission correction, complete private-key redaction, and stale-run reporter checks because they directly protect this slice's validation and issue history.

## Local evidence

Source tree `ff5bd9e40c64032ff0432a482ddb6d86e5805b96` passed 145 security unit tests on each of Arch, Debian, Ubuntu and Fedora. CLI comprehensive counts were Arch 88, Debian 83, Ubuntu 83, Fedora 82; each also passed 6 daemon-optional security target tests. All four product pairs built successfully. These are executed test counts, not newly covered contracts or a 95% claim.

The first CLI launches never reached their tests: the restricted helper PATH omitted `/usr/sbin/runuser`, and CI's `nobody` identity cannot traverse the WSL checkout's ACL. The local runner used absolute `/usr/sbin/runuser` and the existing unprivileged `omg-audit` account. Host permissions and product tests were unchanged; the failed setup attempts are not passing evidence.

The candidate's 86 policy/oracle/admission tests passed on Fedora before the reporting follow-up, followed by 31 reporter tests and all three QA shell harnesses. One reporting invocation used the wrong working directory and failed to find its policy file; the repository-root invocation passed. During the broader follow-up branch validation, Ubuntu Python produced a dictionary SystemError and then SIGSEGV; diagnostics remain in #450. Other interpreter results do not close that environment-dependent failure.

Fresh hosted checks on the resulting PR head remain mandatory before merge. The reviewed behavioral denominator, cross-distro 95% evidence and independent final review are still outstanding.

Final integration check: Arch `cargo fmt --check` and all-target Clippy with `arch,pgp,license` passed after collapsing the advisory fixed-version guard without changing its condition. The subsequent narrow advisory test build crashed in rustc/LLVM `DwarfDebug::finalizeModuleInfo` before executing tests (#451). No retry is credited and the earlier four-distro results do not prove the final syntax change passed its test gate. Preserve this failure and require the fresh hosted candidate gates before integration.

Hosted portable admission on `e30abfa8` exposed a separate owner-resolution defect before test execution: nextest lists the library as `omg`, which prefix matching treated as a second owner of every `omg::integration::test` identity. The [nextest binary ID specification](https://nexte.st/docs/glossary/#binary-id) distinguishes bare library IDs from integration IDs. Native CLI bindings now exclude bare library IDs, while retaining refusal for missing owners, ambiguous integration identities, foreign product pairs and unreviewed tests. Adding the actual library-suite shape to the fixture reproduced the failure; all 18 native-contract tests passed after correction. The failed hosted run remains evidence of the defect, not passing coverage; the new head requires fresh hosted admission.
