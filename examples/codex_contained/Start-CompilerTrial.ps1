param(
    [Parameter(Mandatory=$true)][string]$CompilerRepository,
    [Parameter(Mandatory=$true)][string]$CloudCheckout,
    [ValidateSet('Prepare','Launch','All')][string]$Stage = 'Prepare',
    [string]$Python = 'python',
    [string]$Preparation = 'acceptance-output/compiler-preparation',
    [string]$Auth = "$env:USERPROFILE\.codex\auth.json",
    [string]$Name = ('wf54-57-61-' + (Get-Date -Format 'yyyyMMddHHmmss'))
)
$ErrorActionPreference = 'Stop'
$GuardRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
if (-not (Get-Command $Python -ErrorAction SilentlyContinue)) {
    throw 'Install Python 3.14 and select it with -Python. No operator environment is required.'
}
Push-Location $GuardRoot
try {
    $ErrorActionPreference = 'Continue'
    & $Python examples/codex_contained/prepare_compiler.py --stage $Stage --preparation $Preparation --compiler-repository $CompilerRepository --cloud-checkout $CloudCheckout --auth $Auth --name $Name 2>&1 | ForEach-Object { Write-Output "$_" }
    $NativeExit = $LASTEXITCODE
} finally { Pop-Location }
if ($NativeExit -ne 0) { throw 'Preparation/trial stopped. See retained attempt diagnostics. Do not replay an uncertain write; use a fresh execution name.' }
