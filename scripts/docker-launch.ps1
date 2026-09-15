<#
.SYNOPSIS
    Launch SIH26106 stack with docker-compose
.DESCRIPTION
    Runs preflight checks, then starts docker-compose with proper environment files.
    Supports --no-preflight flag to skip checks.
.NOTES
    Usage: .\scripts\docker-launch.ps1 [--no-preflight] [--build]
#>

param(
    [switch]$NoPreflight,
    [switch]$Build,
    [switch]$Detach
)

$ErrorActionPreference = "Stop"

# Get script directory and project root
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$projectRoot = Split-Path -Parent $scriptDir

Write-Host "=== SIH26106 Docker Launch ===" -ForegroundColor Cyan
Write-Host "Project root: $projectRoot" -ForegroundColor Gray
Write-Host ""

# Change to project root
Set-Location $projectRoot

# Run preflight checks unless skipped
if (-not $NoPreflight) {
    Write-Host "Running preflight checks..." -ForegroundColor Yellow
    & "$scriptDir\preflight.ps1"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Preflight checks failed. Use --no-preflight to skip." -ForegroundColor Red
        exit $LASTEXITCODE
    }
    Write-Host ""
}

# Check for env files
$envFile = "$projectRoot\docker\.env"
$envFrontendFile = "$projectRoot\docker\.env.frontend"

if (-not (Test-Path $envFile)) {
    Write-Host "Creating .env from .env.example..." -ForegroundColor Yellow
    Copy-Item "$projectRoot\docker\.env.example" $envFile
    Write-Host "IMPORTANT: Edit $envFile and set secure passwords!" -ForegroundColor Red
}

if (-not (Test-Path $envFrontendFile)) {
    Write-Host "Creating .env.frontend from .env.example..." -ForegroundColor Yellow
    Copy-Item "$projectRoot\docker\.env.example" $envFrontendFile
}

# Build docker-compose command
$composeCmd = "docker-compose"
if ($Build) {
    $composeCmd += " build"
} else {
    $composeCmd += " up"
}

if ($Detach -or -not $Build) {
    $composeCmd += " -d"
}

Write-Host "Executing: $composeCmd" -ForegroundColor Cyan
Write-Host ""

# Run docker-compose
try {
    Invoke-Expression $composeCmd
} catch {
    Write-Host "Docker-compose failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Show status
Write-Host ""
Write-Host "=== Service Status ===" -ForegroundColor Cyan
docker-compose ps

Write-Host ""
Write-Host "=== Access Points ===" -ForegroundColor Cyan
Write-Host "Frontend:  http://localhost:3000" -ForegroundColor Green
Write-Host "Backend:   http://localhost:8000" -ForegroundColor Green
Write-Host "API Docs:  http://localhost:8000/docs" -ForegroundColor Green
Write-Host "PostgreSQL: localhost:5432" -ForegroundColor Green
Write-Host "Redis:     localhost:6379" -ForegroundColor Green
Write-Host ""
Write-Host "To view logs: docker-compose logs -f [service]" -ForegroundColor Gray
Write-Host "To stop:      .\scripts\docker-stop.ps1" -ForegroundColor Gray
