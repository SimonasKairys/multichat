$ErrorActionPreference = 'Stop'

$tree = cargo tree -d --locked
$versions = @(
    $tree |
        Select-String -Pattern '^crossterm v([0-9]+\.[0-9]+\.[0-9]+)' |
        ForEach-Object { $_.Matches[0].Groups[1].Value } |
        Sort-Object -Unique
)

if ($versions.Count -gt 1) {
    throw "Duplicate crossterm versions detected: $($versions -join ', ')"
}

Write-Host 'OK: crossterm is single-sourced'
