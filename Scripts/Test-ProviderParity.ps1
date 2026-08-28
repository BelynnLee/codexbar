$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'ProviderParity.psm1') -Force
. (Join-Path $PSScriptRoot 'TestHelpers.ps1')

$swiftFixture = @'
public enum UsageProvider: String, CaseIterable {
    case alpha
    case beta = "beta-id"
}

public enum IconStyle: String {
    case ignored
}
'@

$rustFixture = @'
pub enum ProviderId {
    Alpha,
    Beta,
}

impl ProviderId {
    pub const ALL: [Self; 2] = [
        Self::Alpha,
        Self::Beta,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Alpha => "alpha",
            Self::Beta => "beta-id",
        }
    }
}
'@

$typeScriptFixture = @'
export type ProviderId =
  | "alpha"
  | "beta-id";
export type ProviderStatus = "ready" | "error";
'@

Assert-Equal ((Get-SwiftUsageProviderIds -Content $swiftFixture) -join ',') 'alpha,beta-id' 'Swift UsageProvider parsing'
Assert-Equal ((Get-RustRegisteredProviderIds -Content $rustFixture) -join ',') 'alpha,beta-id' 'Rust ProviderId parsing'
Assert-Equal ((Get-TypeScriptProviderIds -Content $typeScriptFixture) -join ',') 'alpha,beta-id' 'TypeScript ProviderId parsing'

$malformedRustMappingFixture = $rustFixture.Replace(
    'Self::Beta => "beta-id"',
    'Self::Beta => beta_id()'
)
Assert-Throws {
    Get-RustRegisteredProviderIds -Content $malformedRustMappingFixture
} 'Missing from Rust ProviderId::as_str() variants: Beta' 'Malformed Rust as_str mapping rejection'

$duplicateTypeScriptFixture = $typeScriptFixture.Replace(
    '| "beta-id";',
    "| `"beta-id`"`n  | `"alpha`";"
)
Assert-Throws {
    Get-TypeScriptProviderIds -Content $duplicateTypeScriptFixture
} "TypeScript ProviderId union contains duplicate id 'alpha'" 'Duplicate TypeScript ProviderId rejection'

Assert-Throws {
    Assert-ExactProviderSet `
        -Expected @('alpha', 'beta-id') `
        -Actual @('alpha', 'unexpected') `
        -ExpectedLabel 'matrix registered entries' `
        -ActualLabel 'TypeScript ProviderId'
} 'Missing from TypeScript ProviderId: beta-id; unexpected in TypeScript ProviderId: unexpected' 'Actionable set differences'

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$matrixPath = Join-Path $repositoryRoot 'docs\provider-parity.json'
$rustPath = Join-Path $repositoryRoot 'crates\codexbar-engine\src\model.rs'
$typeScriptPath = Join-Path $repositoryRoot 'src\types.ts'

$matrixJson = Get-Content -Raw -LiteralPath $matrixPath
$matrix = ConvertFrom-Json -InputObject $matrixJson
$invalidMatrix = ConvertFrom-Json -InputObject $matrixJson
$invalidMatrix[0].sourceModes = 'auto'
Assert-Throws {
    Assert-ProviderParityContract `
        -Matrix $invalidMatrix `
        -RustContent (Get-Content -Raw -LiteralPath $rustPath) `
        -TypeScriptContent (Get-Content -Raw -LiteralPath $typeScriptPath)
} "entry 'codex' field 'sourceModes' must be an array" 'Matrix shape validation'

Assert-ProviderParityContract `
    -Matrix $matrix `
    -RustContent (Get-Content -Raw -LiteralPath $rustPath) `
    -TypeScriptContent (Get-Content -Raw -LiteralPath $typeScriptPath)

Write-Host 'Provider parity validation passed: 60 targets, 59 upstream, 41 registered.'
