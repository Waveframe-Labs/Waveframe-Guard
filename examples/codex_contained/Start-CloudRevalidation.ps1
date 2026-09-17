param(
    [Parameter(Mandatory=$true)][string]$CloudCheckout,
    [string]$Name = ('wf54-57-59-' + (Get-Date -Format 'yyyyMMddHHmmss'))
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
        $ErrorActionPreference = 'Continue'
        & $Executable @Arguments 2>&1 | ForEach-Object { Write-Output "$_" }
        $NativeExit = $LASTEXITCODE
    } finally { $ErrorActionPreference = $PreviousPreference }
    if ($NativeExit -ne 0) { throw "$Executable failed with exit $NativeExit; retain this attempt, do not replay writes" }
}
$ExpectedImages = @{
    'waveframe-guard-54-contained:local' = 'sha256:2af4a2af92444e349c6755ddaf1d4e92fdbd53da8cc2fe51b6a71acbc83bcefb'
    'waveframe-guard-57-writer:local' = 'sha256:86bd888757923cdbc549887e6ec39559a93701bb6f53cc2641c62681bf1fb5fe'
    'waveframe-guard-57-cloud:local' = 'sha256:bc5f71b586ea19056a327fd4077b23ee28eb2af5d5fb42ffa2956f58bed3d9f6'
}
foreach ($ImageName in $ExpectedImages.Keys) {
    $ActualImage = & docker image inspect $ImageName --format '{{.Id}}'
    if ($LASTEXITCODE -ne 0 -or $ActualImage -ne $ExpectedImages[$ImageName]) {
        throw "Accepted image missing or changed: $ImageName. Boundary evidence cannot be reused without matching inputs."
    }
}
$CloudHead = & git -C $CloudCheckout rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or $CloudHead -ne '93bf80f30d170a6be32622a34dbbdf0d85b8ccc6') { throw 'Wrong Cloud head' }
New-Item -ItemType Directory -Path $Output | Out-Null
Invoke-Checked python @('-m','venv',"$Output/operator")
Invoke-Checked $OperatorPython @('-m','pip','install','playwright==1.63.0','requests==2.34.2','--report',"$Output/operator-install.json")
Invoke-Checked $OperatorPython @('-m','playwright','install','chromium')
Invoke-Checked python @('examples/codex_contained/run_cloud.py','cloud','--name',$Name,'--checkout',$CloudCheckout,'--output',"$Output/cloud")
Invoke-Checked $OperatorPython @('examples/codex_contained/console_acceptance.py','approve','--output',"$Output/cloud")
Invoke-Checked $OperatorPython @('examples/codex_contained/revalidate_cloud.py','--name',$Name,'--output',$Output)
Invoke-Checked python @('examples/codex_contained/verify_revalidation.py','--output',$Output)
Write-Host "Captures: $Output. Retain sanitized evidence before the documented cleanup."
