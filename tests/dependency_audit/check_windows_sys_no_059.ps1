$ErrorActionPreference = 'Stop'

$tree = cargo tree -d --locked --target x86_64-pc-windows-msvc
if ($LASTEXITCODE -ne 0) {
    # A native command failing does not trip $ErrorActionPreference; without this
    # guard an empty $tree reads as "windows-sys 0.59.0 absent" and the check
    # silently passes.
    throw "cargo tree failed with exit code ${LASTEXITCODE}; cannot audit windows-sys versions"
}
if ($tree -match '(?m)^windows-sys v0\.59\.0$') {
    throw "windows-sys 0.59.0 is still present in the Windows dependency graph"
}

Write-Host 'OK: windows-sys 0.59.0 is absent from the Windows dependency graph'
