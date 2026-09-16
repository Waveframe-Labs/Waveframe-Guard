param(
    [string]$Name = ('wf54-' + (Get-Date -Format 'yyyyMMdd-HHmmss')),
    [string]$AuthFile = "$env:USERPROFILE/.codex/auth.json",
    [switch]$NoBuild,
    [switch]$NoChat
)
$ErrorActionPreference = 'Stop'
$ProofRoot = (Resolve-Path "$PSScriptRoot/../..").Path
Push-Location $ProofRoot
try {
    if (-not $NoBuild) {
        docker build -t waveframe-guard-54-contained:local -f examples/codex_contained/Dockerfile .
        if ($LASTEXITCODE) { throw 'Image build failed' }
    }
    $ProofOutput = Join-Path $ProofRoot "acceptance-output/$Name"
    python examples/codex_contained/run.py setup --name $Name --output $ProofOutput --auth $AuthFile
    if ($LASTEXITCODE) { throw 'Setup failed; retain output and use documented cleanup' }
    Write-Host "Proof: $Name ; captures: $ProofOutput"
    if (-not $NoChat) {
        python examples/codex_contained/run.py chat --name $Name --output $ProofOutput
    }
} finally { Pop-Location }
