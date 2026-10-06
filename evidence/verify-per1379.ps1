param([string]$BaselineRoot = 'C:/Users/olen/Documents/Codex/paperclip-local/evidence')
$ErrorActionPreference = 'Stop'
$baseline = Get-Content "$BaselineRoot/overnight-github-baseline-20261006.json" -Raw | ConvertFrom-Json
$receipt = Get-Content "$PSScriptRoot/per1379-github-frozen-readback.json" -Raw | ConvertFrom-Json
$metadata = Get-Content "$PSScriptRoot/per1379-github-open-metadata.json" -Raw | ConvertFrom-Json
$audit = Get-Content "$PSScriptRoot/per1379-audit-hash-readback.json" -Raw | ConvertFrom-Json
$prCount = 0
$issueCount = 0
foreach ($repo in $baseline.repositories) {
    foreach ($pr in $repo.prs.items) {
        $match = @($receipt.records | Where-Object { $_.repo -eq $repo.repository -and $_.kind -eq 'pr' -and $_.number -eq $pr.number })
        if ($match.Count -ne 1 -or $match[0].isError -or $match[0].state -ne 'open' -or $match[0].merged -ne $false -or $match[0].head -ne $pr.headRefOid) { throw "Frozen PR mismatch: $($repo.repository)#$($pr.number)" }
        $prCount++
    }
    foreach ($issue in $repo.issues.items) {
        $match = @($receipt.records | Where-Object { $_.repo -eq $repo.repository -and $_.kind -eq 'issue' -and $_.number -eq $issue.number })
        if ($match.Count -ne 1 -or $match[0].isError -or $match[0].state -ne 'open') { throw "Frozen issue mismatch: $($repo.repository)#$($issue.number)" }
        $issueCount++
    }
}
if ($prCount -ne 28 -or $issueCount -ne 33 -or @($receipt.records).Count -ne 61) { throw 'Frozen inventory count mismatch' }
if (@($metadata.records | Where-Object kind -eq 'pr').Count -ne 29 -or @($metadata.records | Where-Object kind -eq 'issue').Count -ne 40) { throw 'Current open inventory count mismatch' }
if (@($metadata.records | Group-Object repo,number | Where-Object Count -ne 1).Count -ne 0) { throw 'Duplicate metadata identity' }
if ($audit.Count -ne 6 -or @($audit | Where-Object { $_.sha256 -notmatch '^[0-9a-f]{64}$' -or $_.result -notlike 'MATCH*' }).Count -ne 0) { throw 'Invalid archived hash receipt' }
$root = Split-Path $PSScriptRoot -Parent
$trackedAudit = (Get-FileHash "$root/.audit/deep-audit.tsv" -Algorithm SHA256).Hash.ToLower()
if ($trackedAudit -ne '139461ab9607df5f2a1c8b17d618f78c8078f357f74365c9444b96ba146977ac') { throw 'Tracked audit changed since prior Intake receipt' }
$paperclip = Get-Content "$BaselineRoot/overnight-paperclip-baseline-20261006.json" -Raw | ConvertFrom-Json
if (-not $paperclip.complete -or @($paperclip.issues).Count -ne 602) { throw 'Paperclip historical baseline incomplete' }
Write-Output 'PASS: 28 frozen PRs open/unmerged/unchanged heads; 33 frozen issues open; 29 current PRs/40 issues; no duplicate identities; six archived source-hash receipts; tracked audit unchanged; historical Paperclip baseline 602.'
Write-Output 'Scope: metadata and archived evidence only; no CI, guest, behavior, fresh-main, or live external audit certification.'
