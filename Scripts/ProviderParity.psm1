Set-StrictMode -Version Latest

function Assert-ExactProviderSet {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$Expected,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$Actual,

        [Parameter(Mandatory)]
        [string]$ExpectedLabel,

        [Parameter(Mandatory)]
        [string]$ActualLabel
    )

    $expectedSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($id in $Expected) {
        $expectedSet.Add($id) | Out-Null
    }
    $actualSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($id in $Actual) {
        $actualSet.Add($id) | Out-Null
    }

    $missing = @($expectedSet | Where-Object { -not $actualSet.Contains($_) } | Sort-Object)
    $unexpected = @($actualSet | Where-Object { -not $expectedSet.Contains($_) } | Sort-Object)
    if ($missing.Count -eq 0 -and $unexpected.Count -eq 0) {
        return
    }

    $differences = [Collections.Generic.List[string]]::new()
    if ($missing.Count -gt 0) {
        $differences.Add("Missing from ${ActualLabel}: $($missing -join ', ')")
    }
    if ($unexpected.Count -gt 0) {
        $differences.Add("unexpected in ${ActualLabel}: $($unexpected -join ', ')")
    }
    throw "$ActualLabel differs from $ExpectedLabel. $($differences -join '; ')."
}

function Get-SwiftUsageProviderIds {
    param(
        [Parameter(Mandatory)]
        [string]$Content
    )

    $enum = [regex]::Match(
        $Content,
        '(?ms)^\s*public\s+enum\s+UsageProvider\b[^\{]*\{(?<body>.*?)^\s*\}'
    )
    if (-not $enum.Success) {
        throw 'Could not find the Swift UsageProvider enum.'
    }

    $cases = [regex]::Matches(
        $enum.Groups['body'].Value,
        '(?m)^\s*case\s+(?<name>[A-Za-z][A-Za-z0-9_]*)(?:\s*=\s*"(?<raw>[^"]+)")?\s*$'
    )
    if ($cases.Count -eq 0) {
        throw 'The Swift UsageProvider enum contains no parseable cases.'
    }

    @($cases | ForEach-Object {
        if ($_.Groups['raw'].Success) {
            $_.Groups['raw'].Value
        } else {
            $_.Groups['name'].Value
        }
    })
}

function Get-RustRegisteredProviderIds {
    param(
        [Parameter(Mandatory)]
        [string]$Content
    )

    $all = [regex]::Match(
        $Content,
        '(?ms)pub\s+const\s+ALL\s*:[^=]+?=\s*\[(?<body>.*?)\];'
    )
    if (-not $all.Success) {
        throw 'Could not find Rust ProviderId::ALL.'
    }
    $allVariants = @(
        [regex]::Matches($all.Groups['body'].Value, 'Self::(?<variant>[A-Za-z][A-Za-z0-9_]*)') |
            ForEach-Object { $_.Groups['variant'].Value }
    )
    if ($allVariants.Count -eq 0) {
        throw 'Rust ProviderId::ALL contains no parseable variants.'
    }
    if (@($allVariants | Sort-Object -Unique).Count -ne $allVariants.Count) {
        throw 'Rust ProviderId::ALL contains duplicate variants.'
    }

    $asString = [regex]::Match(
        $Content,
        "(?ms)pub\s+const\s+fn\s+as_str\s*\([^)]*\)\s*->\s*&'static\s+str\s*\{(?<body>.*?)(?=^\s{4}\})"
    )
    if (-not $asString.Success) {
        throw 'Could not find Rust ProviderId::as_str().'
    }
    $mappings = [regex]::Matches(
        $asString.Groups['body'].Value,
        'Self::(?<variant>[A-Za-z][A-Za-z0-9_]*)\s*=>\s*"(?<id>[^"]+)"'
    )
    if ($mappings.Count -eq 0) {
        throw 'Rust ProviderId::as_str() contains no parseable mappings.'
    }

    $idByVariant = @{}
    foreach ($mapping in $mappings) {
        $variant = $mapping.Groups['variant'].Value
        if ($idByVariant.ContainsKey($variant)) {
            throw "Rust ProviderId::as_str() maps variant '$variant' more than once."
        }
        $idByVariant[$variant] = $mapping.Groups['id'].Value
    }

    Assert-ExactProviderSet `
        -Expected $allVariants `
        -Actual @($idByVariant.Keys) `
        -ExpectedLabel 'Rust ProviderId::ALL variants' `
        -ActualLabel 'Rust ProviderId::as_str() variants'

    @($allVariants | ForEach-Object { $idByVariant[$_] })
}

function Get-TypeScriptProviderIds {
    param(
        [Parameter(Mandatory)]
        [string]$Content
    )

    $union = [regex]::Match(
        $Content,
        '(?ms)export\s+type\s+ProviderId\s*=\s*(?<body>.*?);'
    )
    if (-not $union.Success) {
        throw 'Could not find the TypeScript ProviderId union.'
    }
    $ids = @(
        [regex]::Matches($union.Groups['body'].Value, '["''](?<id>[^"'']+)["'']') |
            ForEach-Object { $_.Groups['id'].Value }
    )
    if ($ids.Count -eq 0) {
        throw 'The TypeScript ProviderId union contains no parseable IDs.'
    }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($id in $ids) {
        if (-not $seen.Add($id)) {
            throw "TypeScript ProviderId union contains duplicate id '$id'."
        }
    }
    $ids
}

function Assert-StringArrayField {
    param(
        [Parameter(Mandatory)]
        [psobject]$Entry,

        [Parameter(Mandatory)]
        [string]$Field,

        [Parameter(Mandatory)]
        [string[]]$AllowedValues
    )

    $id = [string]$Entry.id
    $value = $Entry.$Field
    if ($value -isnot [Array]) {
        throw "Provider parity entry '$id' field '$Field' must be an array."
    }
    if ($value.Count -eq 0) {
        throw "Provider parity entry '$id' field '$Field' must not be empty."
    }
    foreach ($item in $value) {
        if ($item -isnot [string] -or [string]::IsNullOrWhiteSpace($item)) {
            throw "Provider parity entry '$id' field '$Field' must contain only non-empty strings."
        }
        if ($AllowedValues -notcontains $item) {
            throw "Provider parity entry '$id' field '$Field' has unsupported value '$item'."
        }
    }
    if (@($value | Sort-Object -Unique).Count -ne $value.Count) {
        throw "Provider parity entry '$id' field '$Field' contains duplicate values."
    }
}

function Assert-ProviderParityContract {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Matrix,

        [Parameter(Mandatory)]
        [string]$RustContent,

        [Parameter(Mandatory)]
        [string]$TypeScriptContent
    )

    if ($Matrix.Count -ne 60) {
        throw "Provider parity matrix must contain exactly 60 entries; found $($Matrix.Count)."
    }

    $requiredFields = @(
        'id',
        'upstream',
        'registered',
        'maturity',
        'sourceModes',
        'windowsStrategies',
        'liveQa'
    )
    $allowedSourceModes = @('auto', 'api', 'web', 'cli', 'oauth')
    $allowedStrategies = @('apiToken', 'web', 'cli', 'oauth', 'localProbe', 'webDashboard')
    $ids = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)

    foreach ($entry in $Matrix) {
        if ($null -eq $entry) {
            throw 'Provider parity matrix entries must be objects, not null.'
        }
        foreach ($field in $requiredFields) {
            if ($entry.PSObject.Properties.Name -notcontains $field) {
                throw "Provider parity entry is missing required field '$field'."
            }
        }

        if ($entry.id -isnot [string] -or $entry.id -notmatch '^[a-z][a-z0-9]*$') {
            throw "Provider parity field 'id' must be a lowercase alphanumeric string; found '$($entry.id)'."
        }
        if (-not $ids.Add($entry.id)) {
            throw "Provider parity matrix contains duplicate id '$($entry.id)'."
        }
        foreach ($booleanField in @('upstream', 'registered', 'liveQa')) {
            if ($entry.$booleanField -isnot [bool]) {
                throw "Provider parity entry '$($entry.id)' field '$booleanField' must be a boolean."
            }
        }
        if ($entry.maturity -isnot [string] -or @('experimental', 'stable') -notcontains $entry.maturity) {
            throw "Provider parity entry '$($entry.id)' field 'maturity' must be 'experimental' or 'stable'."
        }
        if (-not $entry.registered -and $entry.maturity -ne 'experimental') {
            throw "Unregistered provider '$($entry.id)' must remain experimental."
        }

        Assert-StringArrayField -Entry $entry -Field 'sourceModes' -AllowedValues $allowedSourceModes
        Assert-StringArrayField -Entry $entry -Field 'windowsStrategies' -AllowedValues $allowedStrategies

        if ($entry.PSObject.Properties.Name -contains 'naReason' -and
            ($entry.naReason -isnot [string] -or [string]::IsNullOrWhiteSpace($entry.naReason))) {
            throw "Provider parity entry '$($entry.id)' field 'naReason' must be a non-empty string when present."
        }
    }

    $upstreamIds = @($Matrix | Where-Object { $_.upstream } | ForEach-Object { $_.id })
    $extensionIds = @($Matrix | Where-Object { -not $_.upstream } | ForEach-Object { $_.id })
    $registeredIds = @($Matrix | Where-Object { $_.registered } | ForEach-Object { $_.id })
    if ($upstreamIds.Count -ne 59) {
        throw "Provider parity matrix must contain exactly 59 upstream entries; found $($upstreamIds.Count)."
    }
    Assert-ExactProviderSet `
        -Expected @('opencodezen') `
        -Actual $extensionIds `
        -ExpectedLabel 'the Windows extension set' `
        -ActualLabel 'matrix non-upstream entries'
    if ($registeredIds.Count -ne 41) {
        throw "Provider parity matrix must contain exactly 41 registered entries; found $($registeredIds.Count)."
    }

    $zen = @($Matrix | Where-Object { $_.id -eq 'opencodezen' })[0]
    Assert-ExactProviderSet `
        -Expected @('auto', 'api') `
        -Actual @($zen.sourceModes) `
        -ExpectedLabel 'the Windows OpenCode Zen source modes' `
        -ActualLabel 'matrix opencodezen sourceModes'

    Assert-ExactProviderSet `
        -Expected $registeredIds `
        -Actual @(Get-RustRegisteredProviderIds -Content $RustContent) `
        -ExpectedLabel 'matrix registered entries' `
        -ActualLabel 'Rust ProviderId::ALL/as_str()'
    Assert-ExactProviderSet `
        -Expected $registeredIds `
        -Actual @(Get-TypeScriptProviderIds -Content $TypeScriptContent) `
        -ExpectedLabel 'matrix registered entries' `
        -ActualLabel 'TypeScript ProviderId'
}

Export-ModuleMember -Function @(
    'Assert-ExactProviderSet',
    'Assert-ProviderParityContract',
    'Get-RustRegisteredProviderIds',
    'Get-SwiftUsageProviderIds',
    'Get-TypeScriptProviderIds'
)
