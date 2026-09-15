<#
.SYNOPSIS
    Stop and clean up SIH26106 docker-compose stack
.DESCRIPTION
    Stops all services, removes containers, and optionally removes volumes.
.NOTES
    Usage: .\scripts\docker-stop.ps1 [-RemoveVolumes] [-RemoveImages]
#>

param(
    [switch]$RemoveVolumes,
    [switch]$RemoveImages,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# Get script directory and project root
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$projectRoot = Split-Path -Parent $scriptDir

Write-Host "=== SIH26106 Docker Stop ===" -ForegroundColor Cyan
Write-Host "Project root: $projectRoot" -ForegroundColor Gray
Write-Host ""

# Change to project root
Set-Location $projectRoot

# Confirm if not forced
if (-not $Force) {
    $confirm = Read-Host "This will stop all SIH26106 containers. Continue? (y/N)"
    if ($confirm -notmatch '^[yY]') {
        Write-Host "Cancelled." -ForegroundColor Yellow
        exit 0
    }
}

# Build docker-compose down command
$downCmd = "docker-compose down"
if ($RemoveVolumes) {
    $downCmd += " -v"
    Write-Host "WARNING: Removing volumes (database data will be lost!)" -ForegroundColor Red
}
if ($RemoveImages) {
    $downCmd += " --rmi all"
    Write-Host "WARNING: Removing built images!" -ForegroundColor Red
}

Write-Host "Executing: $downCmd" -ForegroundColor Cyan
Write-Host ""

try {
    Invoke-Expression $downCmd
    Write-Host ""
    Write-Host "=== Stack stopped successfully ===" -ForegroundColor Green
} catch {
    Write-Host "Error stopping stack: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Show remaining resources if any
Write-Host ""
Write-Host "=== Remaining Docker Resources ===" -ForegroundColor Cyan
$containers = docker ps -a --filter "name=sih26106" --format "{{.Names}}\t{{.Status}}"
if ($containers) {
    Write-Host "Containers:" -ForegroundColor Yellow
    Write-Host $containers
} else {
    Write-Host "No SIH26106 containers remaining." -ForegroundColor Green
}

$volumes = docker volume ls --filter "name=sih26106" --format "{{.Name}}"
if ($volumes) {
    Write-Host "Volumes:" -ForegroundColor Yellow
    Write-Host $volumes
    if (-not $RemoveVolumes) {
        Write-Host "Run with -RemoveVolumes to remove these." -ForegroundColor Gray
    }
} else {
    Write-Host "No SIH26106 volumes remaining." -ForegroundColor Green
}

$networks = docker network ls --filter "name=sih26106" --format "{{.Name}}"
if ($networks) {
    Write-Host "Networks:" -ForegroundColor Yellow
    Write-Host $networks
} else {
    Write-Host "No SIH26106 networks remaining." -ForegroundColor Green
}
