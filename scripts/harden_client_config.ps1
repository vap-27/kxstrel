<#
.SYNOPSIS
  Audit/harden an MCP client YAML config that points at the Kxstrel X MCP gateway.

.DESCRIPTION
  Given the path to a client config (e.g. the hermes config.yaml), this helper:

    (a) prints the exact YAML edits the operator must apply: `enabled: true`
        on the server entry and a PINNED bridge version in `args`
        ("-y", "mcp-remote@<version>", <url>, "--header", ...);
    (b) with -Apply, creates a timestamped backup and restricts the file ACL
        to the current user only (inheritance removed);
    (c) never writes or prints the token value. The recommended form is
        "Authorization: Bearer ${MCP_ACCESS_TOKEN}" with the token in an
        environment variable, never inline in the file.

  DRY RUN BY DEFAULT: without -Apply nothing is modified. -Apply is required
  for the backup + ACL changes. Idempotent: re-running detects an identical
  existing backup (by content hash), an already-restricted ACL, and an
  already-pinned version, and reports no changes instead of duplicating work.

  The version pin must match the bridge behaviour actually verified: bump
  $McpRemoteVersion only together with one real tools/call through the new
  bridge version (see docs/invocation.md and docs/token-rotation.md).

  NOTE: this file is deliberately ASCII-only. Windows PowerShell 5.1 reads
  UTF-8-without-BOM scripts as ANSI and mis-parses non-ASCII punctuation.

.EXAMPLE
  # dry run: show the edits, change nothing
  .\scripts\harden_client_config.ps1 -ConfigPath "$env:LOCALAPPDATA\hermes\config.yaml"

.EXAMPLE
  # apply: backup + ACL restriction, still prints the YAML edits
  .\scripts\harden_client_config.ps1 -ConfigPath "$env:LOCALAPPDATA\hermes\config.yaml" -Apply
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ConfigPath,

    # Server entry name inside the config's mcpServers block.
    [string]$ServerName = "kxstrel-x-mcp",

    # Explicit opt-in: without it this script only reports.
    [switch]$Apply,

    # Gateway endpoint to show in the recommended args.
    [string]$GatewayUrl = "https://<your-x-mcp-host>/mcp",

    # Pinned bridge version. MUST match the bridge behaviour actually verified
    # end-to-end (handshake + tools/list + one real tools/call).
    [string]$McpRemoteVersion = "0.14.0"
)

$ErrorActionPreference = "Stop"

function Write-Section([string]$Text) {
    Write-Host ""
    Write-Host "=== $Text ===" -ForegroundColor Cyan
}

Write-Host "Kxstrel X MCP client config hardening" -ForegroundColor Green
Write-Host "recommended pinned bridge version: mcp-remote@$McpRemoteVersion"
Write-Host "mode: $(if ($Apply) { 'APPLY (backup + ACL)' } else { 'dry run (no changes)' })"

# --- 0. locate the config --------------------------------------------------
$resolved = $null
if (Test-Path -LiteralPath $ConfigPath) {
    $resolved = (Resolve-Path -LiteralPath $ConfigPath).Path
} else {
    Write-Host "[FAIL] config not found: $ConfigPath" -ForegroundColor Red
    Write-Host "       Create it in your MCP client first, then re-run this helper."
    exit 2
}
$item = Get-Item -LiteralPath $resolved
Write-Host "[ok] config: $resolved ($($item.Length) bytes)"

$raw = Get-Content -LiteralPath $resolved -Raw
$lines = Get-Content -LiteralPath $resolved

# --- 1. safety scans (never print the secret value) ------------------------
Write-Section "Secret handling"

$inlineBearer = [regex]::Matches($raw, 'Bearer\s+[A-Za-z0-9_\-\.]{20,}')
if ($inlineBearer.Count -gt 0) {
    Write-Host "[WARN] $($inlineBearer.Count) inline bearer value(s) found in this file." -ForegroundColor Yellow
    Write-Host "       Move the token to an environment variable and reference it as"
    Write-Host "       'Authorization: Bearer `${MCP_ACCESS_TOKEN}' instead. The value is NOT printed here."
} else {
    Write-Host "[ok] no inline bearer token detected"
}

foreach ($name in @("ADMIN_TOKEN", "MCP_ACCESS_TOKEN", "CREDENTIAL_ENCRYPTION_KEY")) {
    if ((Split-Path -Leaf $resolved) -eq $name) {
        Write-Host "[WARN] this path looks like a token file, not a client config." -ForegroundColor Yellow
    }
}

# --- 2. current state: enabled flag + pinned version ----------------------
Write-Section "Current config state"

$enabledLine = $lines | Select-String -Pattern "^\s*enabled\s*:" | Select-Object -First 1
if ($enabledLine) {
    Write-Host "[ok] enabled key present (line $($enabledLine.LineNumber)): $($enabledLine.Line.Trim())"
} else {
    Write-Host "[TODO] no enabled key found - add 'enabled: true' to the server entry."
}

$versionPin = $lines | Select-String -Pattern "mcp-remote@" | Select-Object -First 1
if ($versionPin) {
    Write-Host "[ok] bridge version pinned (line $($versionPin.LineNumber)): $($versionPin.Line.Trim())"
} else {
    $floating = $lines | Select-String -Pattern "mcp-remote" | Select-Object -First 1
    if ($floating) {
        Write-Host "[TODO] floating bridge version on line $($floating.LineNumber): $($floating.Line.Trim())"
        Write-Host "       Pin it as 'mcp-remote@$McpRemoteVersion' so npx cannot drift between builds."
    } else {
        Write-Host "[TODO] no mcp-remote entry found; see the recommended block below."
    }
}

$headerLine = $lines | Select-String -Pattern "Authorization\s*:\s*Bearer" | Select-Object -First 1
if ($headerLine) {
    if ($headerLine.Line -match '\$\{?[A-Za-z_]') {
        Write-Host "[ok] Authorization header uses environment indirection"
    } else {
        Write-Host "[WARN] Authorization header looks literal (line $($headerLine.LineNumber)); prefer the env form."
    }
}

# --- 3. the exact YAML the operator must apply ----------------------------
Write-Section "Apply these YAML edits"

# Built from single-quoted literals (no here-string, no interpolation) so the
# script parses identically under Windows PowerShell 5.1 and PowerShell 7.
$yamlBlock = @(
    'mcpServers:'
    ('  {0}:' -f $ServerName)
    '    enabled: true                     # (a) explicit, matches your working entries'
    '    command: npx'
    '    args:'
    '      - "-y"'
    ('      - "mcp-remote@{0}"   # (b) PINNED bridge version' -f $McpRemoteVersion)
    ('      - "{0}"' -f $GatewayUrl)
    '      - "--header"'
    '      - "Authorization: Bearer ${MCP_ACCESS_TOKEN}"   # token comes from the environment'
) -join [Environment]::NewLine
Write-Host $yamlBlock
Write-Host ""
Write-Host "Notes:"
Write-Host "  - The version pin must match the bridge behaviour you actually verified:"
Write-Host "    after changing it, run one real call (scripts/live_mcp_probe.py --live)."
Write-Host "  - Keep the token in an environment variable; never inline it in this file."
Write-Host "  - The gateway declares a static header bearer token with an EMPTY"
Write-Host "    authorization_servers list at /.well-known/oauth-protected-resource,"
Write-Host "    so a spec-compliant bridge fails fast instead of attempting OAuth."

# --- 4. backup (apply mode) ------------------------------------------------
Write-Section "Backup"

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backupPath = "$resolved.$stamp.bak"
$hash = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash

$existingBackups = @(Get-ChildItem -LiteralPath (Split-Path -Parent $resolved) `
    -Filter "$(Split-Path -Leaf $resolved).*.bak" -ErrorAction SilentlyContinue)
$sameContent = $null
foreach ($candidate in $existingBackups) {
    if ((Get-FileHash -LiteralPath $candidate.FullName -Algorithm SHA256).Hash -eq $hash) {
        $sameContent = $candidate.FullName
        break
    }
}

if (-not $Apply) {
    Write-Host "[dry-run] would create backup: $backupPath"
} elseif ($sameContent) {
    Write-Host "[skip] an identical backup already exists: $sameContent"
} else {
    Copy-Item -LiteralPath $resolved -Destination $backupPath -Force
    Write-Host "[ok] backup created: $backupPath"
}

# --- 5. ACL restriction (apply mode) --------------------------------------
Write-Section "ACL (current user only)"

# Resolve the caller's identity robustly (env vars can be absent in some
# shells; WindowsIdentity is authoritative for ACL work).
$currentUser = $null
try {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
} catch {
    $currentUser = $null
}
if (-not $currentUser) {
    $currentUser = "$env:USERDOMAIN\$env:USERNAME"
}

try {
    $acl = Get-Acl -LiteralPath $resolved
    $otherRules = @($acl.Access | Where-Object { $_.IdentityReference.Value -ne $currentUser })
    $inheritanceProtected = $acl.AreAccessRulesProtected

    if ($inheritanceProtected -and $otherRules.Count -eq 0) {
        Write-Host "[ok] ACL already restricts access to $currentUser (inheritance off)"
    } elseif (-not $Apply) {
        Write-Host "[dry-run] would set ACL: inheritance off, only ${currentUser}:FullControl"
        Write-Host "          current owner: $($acl.Owner); other rules: $($otherRules.Count)"
    } else {
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($rule in @($acl.Access)) {
            [void]$acl.RemoveAccessRule($rule)
        }
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $currentUser, "FullControl", "Allow")
        $acl.SetAccessRule($rule)
        Set-Acl -LiteralPath $resolved -AclObject $acl
        $verify = Get-Acl -LiteralPath $resolved
        $remaining = @($verify.Access | Where-Object { $_.IdentityReference.Value -ne $currentUser })
        if ($remaining.Count -eq 0) {
            Write-Host "[ok] ACL restricted to $currentUser (inheritance off)"
        } else {
            Write-Host "[WARN] $($remaining.Count) extra ACL rule(s) remain; inspect manually." -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "[FAIL] ACL operation failed: $($_.Exception.Message)" -ForegroundColor Red
    if ($Apply) { exit 1 }
}

# --- done -----------------------------------------------------------------
Write-Section "Done"
if (-not $Apply) {
    Write-Host "Dry run complete: nothing was modified. Re-run with -Apply to create the backup and restrict the ACL."
    Write-Host "The YAML edits above are still yours to apply to the config."
}
exit 0
