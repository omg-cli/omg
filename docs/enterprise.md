---
title: Enterprise reports and export limits
sidebar_position: 46
description: Observed reports, inventory exports, and unsupported compliance controls
---

# Enterprise reports and export limits

**In plain words:** Reports and policies aimed at organisations, with the limit of each report stated plainly.

> New to the terminal? Read [Getting started](./getting-started.md) and keep
> [the glossary](./glossary.md) open while you work.

The `enterprise` commands expose reports, dashboard policy views, and local inventory exports. They do not certify regulatory compliance, implement HIPAA controls, or provide an encrypted evidence archive. Local CLI features are not a paid-tier security boundary. Dashboard operations still require working account access and a reachable service.

## Reports

```bash
omg enterprise reports --report-type monthly
```

Report types are `monthly`, `quarterly`, and `custom`. The JSON contains a fetched fleet-machine count and observed validation-failure, rate-limit, and security-audit-request counters from the current process. The report type labels the report; it does not query a month's historical metrics. A failed fleet lookup returns an error instead of an invented count.

Reports do not calculate savings, remediation totals, or compliance scores.

## Audit export

```bash
omg enterprise audit-export --framework soc2 --output ./evidence
```

This command requires the Arch backend for installed-package inventory. It writes:

- `limitations.json`, including the absence of an authoritative access-control matrix.
- `change-log.json`, up to 100 recent local audit entries.
- `policy-enforcement.json`, the loaded local policy, not a history of enforcement decisions.
- `installed-packages.csv`, the observed installed-package inventory.
- `sbom-inventory.json`, a CycloneDX 1.5 component inventory without resolved dependency edges or vulnerability scanning.

The parser accepts `soc2`, `iso27001`, `fedramp`, `hipaa`, and `pci-dss`. These names select no different evidence generators here. `--period` is displayed as a label and does not filter records. A successful generic export is not evidence that the named framework's controls are implemented.

This differs from `omg audit export`, where only `soc2` generates evidence and the other framework names fail as unimplemented. See [security exports](./security.md#compliance-exports).

Exports are plaintext. This bundle uses owner-only file permissions, not encryption, signing, or independent timestamping. Report and license-export writers do not all use the same private writer. Restrict the destination, inspect permissions and contents, and apply your organization's encryption and retention controls. A failed write can leave a partial bundle. Reusing an output directory can overwrite files.

## License inventory

```bash
omg enterprise license-scan
omg enterprise license-scan --export csv
omg enterprise license-scan --export json
```

This command reads installed Arch package license metadata. It reports unknown licenses and flags GPL-containing labels for legal review. It does not scan an application's dependency tree or interpret your organization's full legal policy. Percentages count license assignments; a package can have multiple assignments.

CSV output aggregates license counts. JSON includes the scan result. Neither format is an SPDX export. These reports are inputs to review, not legal conclusions.

## Policy view

```bash
omg enterprise policy show
omg enterprise policy show --scope global
```

This fetches dashboard policies and optionally filters their scope. It does not edit policy. A remote policy's `enforced` label is not proof that every local backend enforces it.

The local host policy at `~/.config/omg/policy.toml` is separate and is shown by `omg audit policy`. See [backend enforcement limits](./security.md#security-policy).

## Self-hosting

OMG provides no self-hosted registry initialization or package mirroring commands. Use each package ecosystem's native mirroring tools.

## Where to go next

- [Security model](./security.md) for the scope of scans, audit logs, and SOC 2 export.
- [Configuration](./configuration.md) for the local policy file.
- [CLI reference](./cli.md) for accepted command options.
