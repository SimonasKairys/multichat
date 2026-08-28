$ErrorActionPreference = 'Stop'

$tree = cargo tree -d --locked --target x86_64-pc-windows-msvc
if ($tree -match '(?m)^windows-sys v0\.59\.0$') {
    throw "windows-sys 0.59.0 is still present in the Windows dependency graph"
}

Write-Host 'OK: windows-sys 0.59.0 is absent from the Windows dependency graph'
