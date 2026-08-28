#requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$tracked = @(git -C $repositoryRoot ls-files)
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to enumerate tracked files for the public-surface check.'
}

$violations = [System.Collections.Generic.List[string]]::new()
$forbiddenPathPatterns = @(
    '^\.gitea(?:/|$)',
    '^AGENTS\.md$',
    '^docs/superpowers(?:/|$)',
    '^docs/(?:UPSTREAM_STRATEGY|RELEASING)\.md$',
    '^docs/.*(?:analysis|simulation|validation).*\.md$',
    '^Scripts/(?:Install-GiteaRunner|New-WindowsRelease|Prepare-WindowsRelease|Publish-UpdaterManifest|Publish-WindowsDraft|release)\.ps1$',
    '^Scripts/(?:ReleaseTools|RunnerTools)\.psm1$',
    '^Scripts/Test-(?:InternalRelease|PrepareWindowsRelease|ReleaseTools|RunnerTools)\.ps1$',
    '(^|/)[^/]+\.(?:env|local|key|pem|p12|pfx|cer|mobileprovision)$',
    '(^|/)(?:release|secrets)(?:/|$)',
    '\.(?:app|ipa|dSYM|exe|msi|pdb|zip)$'
)

$forbiddenContentPatterns = [ordered]@{
    'private Gitea host' = 'git\.' + 'belynn' + '\.top'
    'Gitea secret name' = '(?i)\b' + 'GITEA' + '_[A-Z0-9_]*\b'
    'embedded updater token' = 'CODEXBAR_' + 'UPDATER_' + 'TOKEN'
    'macOS absolute path' = '(?-i:/' + 'Users' + '/[A-Za-z0-9._-]+)'
    'private-key PEM marker' = '-----BEGIN\s+(?:[A-Z]+\s+)?PRIVATE KEY-----'
    'known real email' = '(?i)(?:steipete' + '@gmail\.com|brandon' + '@topoffunnel\.com|belynn125' + '@gmail\.com)'
}

$binaryExtensions = @(
    '.7z', '.app', '.bmp', '.dmg', '.dylib', '.exe', '.gif', '.ico', '.ipa', '.jpeg', '.jpg',
    '.msi', '.pdf', '.pdb', '.png', '.so', '.ttf', '.woff', '.woff2', '.zip'
)

foreach ($path in $tracked) {
    foreach ($pattern in $forbiddenPathPatterns) {
        if ($path -match $pattern) {
            [void]$violations.Add("forbidden tracked path: $path")
            break
        }
    }

    $fullPath = Join-Path $repositoryRoot ($path -replace '/', '\')
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        continue
    }
    if ($binaryExtensions -contains ([IO.Path]::GetExtension($fullPath).ToLowerInvariant())) {
        continue
    }

    $content = [IO.File]::ReadAllText($fullPath)
    foreach ($entry in $forbiddenContentPatterns.GetEnumerator()) {
        if ($content -match $entry.Value) {
            [void]$violations.Add("$($entry.Key): $path")
        }
    }
}

if ($violations.Count -gt 0) {
    $details = $violations -join [Environment]::NewLine
    throw "Public-surface check failed:`n$details"
}

Write-Host "Public-surface check passed for $($tracked.Count) tracked files."
