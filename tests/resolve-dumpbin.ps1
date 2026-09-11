$ErrorActionPreference = "Stop"

$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
    throw "vswhere.exe was not found at the canonical Visual Studio Installer path: $vswhere"
}
$installation = (& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath).Trim()
if (-not $installation -or -not (Test-Path -LiteralPath $installation -PathType Container)) {
    throw "vswhere found no Visual Studio installation containing the x64 MSVC tools"
}
$vcvars = Join-Path $installation "VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path -LiteralPath $vcvars -PathType Leaf)) {
    throw "vcvars64.bat is missing from the selected MSVC installation: $vcvars"
}
# Resolve using the same vcvars environment a native x64 developer prompt uses.
$environment = & $env:COMSPEC /d /s /c "`"$vcvars`" >nul && set"
if ($LASTEXITCODE -ne 0) { throw "vcvars64.bat failed with exit code $LASTEXITCODE" }
foreach ($line in $environment) {
    if ($line -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process') }
}
$dumpbin = (Get-Command dumpbin.exe -CommandType Application -ErrorAction Stop).Source
$normalizedRoot = [IO.Path]::GetFullPath($installation).TrimEnd('\') + '\'
$normalizedDumpbin = [IO.Path]::GetFullPath($dumpbin)
if (-not $normalizedDumpbin.StartsWith($normalizedRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "resolved dumpbin is outside the vswhere-selected installation: $normalizedDumpbin"
}
if ($env:GITHUB_OUTPUT) { "path=$normalizedDumpbin" | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding utf8 -Append }
Write-Host "Resolved dumpbin: $normalizedDumpbin"
