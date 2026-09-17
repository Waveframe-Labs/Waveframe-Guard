param(
    [Parameter(Mandatory=$true)][string]$CompilerRepository,
    [Parameter(Mandatory=$true)][string]$CloudCheckout,
    [Parameter(Mandatory=$true)][string]$OperatorPython,
    [string]$Name = ('wf54-57-61-' + (Get-Date -Format 'yyyyMMddHHmmss'))
)
$ErrorActionPreference = 'Stop'
$GuardRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Set-Location $GuardRoot
# The Python driver retains failed steps and never replays a mutation automatically.
# OperatorPython must have requests and Playwright/Chromium ready (documented prerequisite).
$PreviousPreference = $ErrorActionPreference
try {
    $ErrorActionPreference = 'Continue'
    & $OperatorPython examples/codex_contained/compiler_trial.py --name $Name --output "acceptance-output/$Name" --compiler-repository $CompilerRepository --cloud-checkout $CloudCheckout 2>&1 | ForEach-Object { Write-Output "$_" }
    $NativeExit = $LASTEXITCODE
} finally { $ErrorActionPreference = $PreviousPreference }
if ($NativeExit -ne 0) { throw "Compiler trial failed with exit $NativeExit. Retain the attempt; do not replay writes." }
Write-Host "Patch and results: acceptance-output/$Name. Retain evidence before documented cleanup."
