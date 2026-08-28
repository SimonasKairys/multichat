$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$ciPath = Join-Path $repoRoot '.github\workflows\ci.yml'
$ciText = Get-Content -Raw -LiteralPath $ciPath

$required = @(
    @{ name = 'cargo clippy'; pattern = 'cargo clippy\b(?!.*--locked)' },
    @{ name = 'cargo test'; pattern = 'cargo test\b(?!.*--locked)' },
    @{ name = 'cargo build'; pattern = 'cargo build\b(?!.*--locked)' }
)

foreach ($item in $required) {
    if ($ciText -match $item.pattern) {
        throw "CI command missing --locked: $($item.name)"
    }
}

Write-Host 'OK: CI cargo commands are locked'
