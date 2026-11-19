# Reproduce the VYRA Kani run on Windows with Docker Desktop (Linux containers).
#   powershell -File tools\kani\run.ps1 [-OutDir <dir>] [-HarnessTimeout 1200] [-Jobs 4]
# Builds the pinned image (tools/kani/Dockerfile), runs every harness (the
# signature harness included) and every mutant in a container with the
# repository mounted READ-ONLY, then copies the raw report to
# results\kani-report.txt. Exits non-zero if any harness is not SUCCESSFUL
# (FAILED, TIMEOUT or ERROR) or any mutant outcome differs from
# tools\kani\mutants.tsv.
param(
    [string]$OutDir = (Join-Path ([System.IO.Path]::GetTempPath()) "vyra-kani-out"),
    [int]$HarnessTimeout = 1200,
    [int]$Jobs = 4
)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = (Resolve-Path (Join-Path $here "..\..")).Path
$image = "vyra-kani:0.68.0"
New-Item -ItemType Directory -Force $OutDir | Out-Null

docker info --format "{{.ServerVersion}}" | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Error "Docker daemon not reachable; start Docker Desktop first." }

docker build -t $image $here
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

docker run --rm -e "HARNESS_TIMEOUT=$HarnessTimeout" -e "KANI_JOBS=$Jobs" `
    -v "${repo}:/repo:ro" -v "${OutDir}:/out" `
    $image bash /repo/tools/kani/in-container.sh
$rc = $LASTEXITCODE

$report = Join-Path $OutDir "kani-report.txt"
if (Test-Path $report) {
    # Append without a BOM (PowerShell 5.1 Out-File -Encoding utf8 writes one).
    $id = (docker image inspect --format "{{.Id}}" $image | Out-String).Trim()
    [System.IO.File]::AppendAllText($report, "image $id`n", (New-Object System.Text.UTF8Encoding($false)))
    Copy-Item $report (Join-Path $repo "results\kani-report.txt") -Force
    Write-Host "report: $(Join-Path $repo 'results\kani-report.txt') (exit $rc)"
} else {
    Write-Host "no report produced (exit $rc)"
    if ($rc -eq 0) { $rc = 1 }
}
exit $rc
