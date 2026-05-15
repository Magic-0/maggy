#Requires -Version 5.1
<#
.SYNOPSIS
    Synchronise le fork Magic-0/maggy avec l'upstream alinaqi/maggy.
#>
[CmdletBinding()]
param([switch]$SkipInstall)

$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    Write-Host "==> Fetch upstream (alinaqi/maggy)..." -ForegroundColor Cyan
    git fetch upstream --prune

    $new = git log HEAD..'upstream/main' --oneline
    if (-not $new) { Write-Host "Deja a jour." -ForegroundColor Green; return }

    Write-Host "==> Nouveaux commits :" -ForegroundColor Yellow
    $new | ForEach-Object { Write-Host "  $_" }

    Write-Host "`n==> Merge upstream/main..." -ForegroundColor Cyan
    git merge upstream/main --no-edit
    if ($LASTEXITCODE -ne 0) { Write-Error "Conflit — resous puis relance."; exit 1 }

    Write-Host "==> Push vers Magic-0/maggy..." -ForegroundColor Cyan
    git push origin main

    if (-not $SkipInstall) {
        $bash = Get-Command bash -ErrorAction SilentlyContinue
        if ($bash) {
            Write-Host "`n==> Reinstallation des skills/hooks..." -ForegroundColor Cyan
            & $bash.Source './install.sh'
        } else {
            Write-Warning "bash introuvable — lance ./install.sh manuellement via Git Bash."
        }
    }

    Write-Host "`nSync termine." -ForegroundColor Green
} finally {
    Pop-Location
}
