<#
.SYNOPSIS
    Pre-flight checks for SIH26106 Docker deployment
.DESCRIPTION
    Verifies that required host-local services (Ollama, Hardhat) are running
    before starting docker-compose. Exits with non-zero code if checks fail.
.NOTES
    Run this before: docker-compose up -d
#>

param(
    [string]$OllamaUrl = "http://localhost:11434",
    [string]$HardhatUrl = "http://localhost:8545",
    [int]$OllamaTimeout = 10,
    [int]$HardhatTimeout = 10
)

$ErrorActionPreference = "Stop"

Write-Host "=== SIH26106 Pre-flight Checks ===" -ForegroundColor Cyan
Write-Host ""

$allChecksPassed = $true

# Check 1: Ollama service
Write-Host "[1/3] Checking Ollama at $OllamaUrl..." -NoNewline
try {
    $ollamaResponse = Invoke-RestMethod -Uri "$OllamaUrl/api/tags" -Method Get -TimeoutSec $OllamaTimeout -ErrorAction Stop
    if ($ollamaResponse.models) {
        $modelNames = $ollamaResponse.models | Select-Object -ExpandProperty name
        Write-Host " OK" -ForegroundColor Green
        Write-Host "       Available models: $($modelNames -join ', ')"
        
        # Check for required model
        if ($modelNames -contains "llama3.2:3b") {
            Write-Host "       Required model 'llama3.2:3b' found" -ForegroundColor Green
        } else {
            Write-Host "       WARNING: Required model 'llama3.2:3b' not found!" -ForegroundColor Yellow
            Write-Host "       Run: ollama pull llama3.2:3b" -ForegroundColor Yellow
        }
    } else {
        Write-Host " FAILED - No models found" -ForegroundColor Red
        $allChecksPassed = $false
    }
} catch {
    Write-Host " FAILED" -ForegroundColor Red
    Write-Host "       Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "       Make sure Ollama is running: ollama serve" -ForegroundColor Red
    $allChecksPassed = $false
}

# Check 2: Hardhat node
Write-Host "[2/3] Checking Hardhat at $HardhatUrl..." -NoNewline
try {
    $hardhatResponse = Invoke-RestMethod -Uri $HardhatUrl -Method Post -Body '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' -ContentType "application/json" -TimeoutSec $HardhatTimeout -ErrorAction Stop
    if ($hardhatResponse.result) {
        $blockNumber = [Convert]::ToInt64($hardhatResponse.result, 16)
        Write-Host " OK" -ForegroundColor Green
        Write-Host "       Current block: $blockNumber"
    } else {
        Write-Host " FAILED - Invalid response" -ForegroundColor Red
        $allChecksPassed = $false
    }
} catch {
    Write-Host " FAILED" -ForegroundColor Red
    Write-Host "       Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "       Make sure Hardhat node is running: npx hardhat node" -ForegroundColor Red
    $allChecksPassed = $false
}

# Check 3: Docker daemon
Write-Host "[3/3] Checking Docker daemon..." -NoNewline
try {
    $dockerInfo = docker version --format '{{.Server.Version}}' 2>$null
    if ($dockerInfo) {
        Write-Host " OK" -ForegroundColor Green
        Write-Host "       Docker version: $dockerInfo"
    } else {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Host "       Docker daemon not responding" -ForegroundColor Red
        $allChecksPassed = $false
    }
} catch {
    Write-Host " FAILED" -ForegroundColor Red
    Write-Host "       Error: $($_.Exception.Message)" -ForegroundColor Red
    $allChecksPassed = $false
}

Write-Host ""
if ($allChecksPassed) {
    Write-Host "=== All pre-flight checks PASSED ===" -ForegroundColor Green
    Write-Host "You can now run: docker-compose up -d" -ForegroundColor Cyan
    exit 0
} else {
    Write-Host "=== Some pre-flight checks FAILED ===" -ForegroundColor Red
    Write-Host "Please resolve the issues above before starting docker-compose." -ForegroundColor Red
    exit 1
}
