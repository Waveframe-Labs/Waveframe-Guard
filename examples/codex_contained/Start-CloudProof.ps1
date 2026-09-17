param(
    [Parameter(Mandatory=$true)][string]$CloudCheckout,
    [string]$Name = ('wf54-57-' + (Get-Date -Format 'yyyyMMddHHmmss')),
    [switch]$NoBuild
)
$ErrorActionPreference = 'Stop'
$GuardRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Set-Location $GuardRoot
$Output = "acceptance-output/$Name"
$OperatorPython = "$Output/operator/Scripts/python.exe"
function Invoke-Checked {
    param([string]$Executable, [string[]]$Arguments)
    $PreviousPreference = $ErrorActionPreference
    try {
        # Windows PowerShell treats native stderr notices as error records.
        # The native exit status, including real failures, remains authoritative.
        $ErrorActionPreference = 'Continue'
        & $Executable @Arguments 2>&1 | ForEach-Object { Write-Output "$_" }
        $NativeExit = $LASTEXITCODE
    } finally { $ErrorActionPreference = $PreviousPreference }
    if ($NativeExit -ne 0) { throw "$Executable failed with exit $NativeExit; retain this attempt" }
}
New-Item -ItemType Directory -Path $Output | Out-Null
Invoke-Checked python @('-m','venv',"$Output/operator")
Invoke-Checked $OperatorPython @('-m','pip','install','playwright==1.63.0','requests==2.34.2','--report',"$Output/operator-install.json")
Invoke-Checked $OperatorPython @('-m','playwright','install','chromium')
if (-not $NoBuild) {
    Invoke-Checked docker @('build','-t','waveframe-guard-54-contained:local','-f','examples/codex_contained/Dockerfile','.')
    Invoke-Checked docker @('build','-t','waveframe-guard-57-writer:local','-f','examples/codex_contained/Dockerfile.writer','.')
    Invoke-Checked docker @('build','--build-context',"cloud=$CloudCheckout",'-t','waveframe-guard-57-cloud:local','-f','examples/codex_contained/Dockerfile.cloud','.')
}
Invoke-Checked python @('examples/codex_contained/run_cloud.py','cloud','--name',$Name,'--checkout',$CloudCheckout,'--output',"$Output/cloud")
Invoke-Checked $OperatorPython @('examples/codex_contained/console_acceptance.py','approve','--output',"$Output/cloud")
$UsefulStarted = Get-Date
Invoke-Checked python @('examples/codex_contained/run_cloud.py','client','--name',$Name,'--output',"$Output/client",'--config',"$Output/cloud/writer-private.json",'--auth',"$env:USERPROFILE/.codex/auth.json")
Invoke-Checked python @('examples/codex_contained/run.py','chat','--name',$Name,'--output',"$Output/client",'--phase','allowed','--prompt','examples/codex_contained/prompts/cloud-allowed.txt')
[ordered]@{ prerequisites = 'Docker Linux engine, authenticated Codex cache, images, browser, fresh approval and runtime credentials already ready'; setup_to_completed_turn_seconds = ((Get-Date) - $UsefulStarted).TotalSeconds } | ConvertTo-Json | Set-Content "$Output/useful-timing.json"
Invoke-Checked python @('examples/codex_contained/run.py','capture','--name',$Name,'--output',"$Output/client")
Write-Host "Disposable proof: $Name; output: $Output. Inspect the recorded tool results and bytes before claiming acceptance."
