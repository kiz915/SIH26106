<# 
.SYNOPSIS
    SIH26106 Integration Sprint - Full Stack Launcher
    Starts Hardhat node -> Deploys contract -> Starts Backend -> Prints Frontend URL
#>

param(
    [switch]$SkipBlockchain,
    [switch]$SkipBackend,
    [switch]$SkipFrontend
)

$ErrorActionPreference = "Stop"
$RepoRoot = "D:\SIH26106"

Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "  SIH26106 ThreatLens - Full Stack Launcher" -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Cyan
Write-Host ""

# Check prerequisites
Write-Host "[*] Checking prerequisites..." -ForegroundColor Yellow

# Check Node.js
try {
    $nodeVersion = node --version
    Write-Host "    Node.js: $nodeVersion" -ForegroundColor Green
} catch {
    Write-Host "    [ERROR] Node.js not found. Please install Node.js 18+" -ForegroundColor Red
    exit 1
}

# Check Python
try {
    $pythonVersion = python --version
    Write-Host "    Python: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "    [ERROR] Python not found. Please install Python 3.10+" -ForegroundColor Red
    exit 1
}

# Check npm
try {
    $npmVersion = npm --version
    Write-Host "    npm: $npmVersion" -ForegroundColor Green
} catch {
    Write-Host "    [ERROR] npm not found" -ForegroundColor Red
    exit 1
}

Write-Host ""

# ============================================
# 1. BLOCKCHAIN: Start Hardhat node & deploy
# ============================================
if (-not $SkipBlockchain) {
    Write-Host "[1/3] Starting Blockchain (Hardhat)..." -ForegroundColor Yellow
    
    $blockchainDir = Join-Path $RepoRoot "blockchain"
    Set-Location $blockchainDir
    
    # Install dependencies if needed
    if (-not (Test-Path "node_modules")) {
        Write-Host "    Installing blockchain dependencies..." -ForegroundColor Yellow
        npm install
    }
    
    # Start Hardhat node in background
    Write-Host "    Starting Hardhat node on http://127.0.0.1:8545..." -ForegroundColor Yellow
    $hardhatNode = Start-Process -FilePath "npx" -ArgumentList "hardhat", "node" -WorkingDirectory $blockchainDir -PassThru -WindowStyle Hidden
    
    # Wait for node to be ready
    Start-Sleep -Seconds 5
    
    # Deploy contract
    Write-Host "    Deploying EvidenceRegistry contract..." -ForegroundColor Yellow
    $deployResult = npx hardhat run scripts/deploy.js --network localhost 2>&1
    Write-Host "    $deployResult" -ForegroundColor Gray
    
    # Extract contract address
    if ($deployResult -match 'deployed to:\s+(0x[a-fA-F0-9]{40})') {
        $contractAddress = $matches[1]
        Write-Host "    Contract deployed: $contractAddress" -ForegroundColor Green
        
        # Save to backend .env
        $backendEnv = Join-Path $RepoRoot "backend\.env"
        $envContent = @"
BLOCKCHAIN_RPC_URL=http://127.0.0.1:8545
BLOCKCHAIN_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
BLOCKCHAIN_CONTRACT_ADDRESS=$contractAddress
SIH_EVIDENCE_DIR=data/evidence
"@
        Set-Content -Path $backendEnv -Value $envContent
        Write-Host "    Backend .env updated with contract address" -ForegroundColor Green
    }
    
    Set-Location $RepoRoot
    Write-Host ""
}

# ============================================
# 2. BACKEND: Start FastAPI (uvicorn)
# ============================================
if (-not $SkipBackend) {
    Write-Host "[2/3] Starting Backend (FastAPI)..." -ForegroundColor Yellow
    
    $backendDir = Join-Path $RepoRoot "backend"
    Set-Location $backendDir
    
    # Install Python dependencies if needed
    if (-not (Test-Path ".venv")) {
        Write-Host "    Creating Python virtual environment..." -ForegroundColor Yellow
        python -m venv .venv
    }
    
    # Activate venv and install requirements
    Write-Host "    Installing backend dependencies..." -ForegroundColor Yellow
    & "$backendDir\.venv\Scripts\pip.exe" install -r requirements.txt -q
    
    # Start uvicorn in background
    Write-Host "    Starting FastAPI on http://localhost:8000..." -ForegroundColor Yellow
    $backendProcess = Start-Process -FilePath "$backendDir\.venv\Scripts\uvicorn.exe" `
        -ArgumentList "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload" `
        -WorkingDirectory $backendDir -PassThru -WindowStyle Hidden
    
    # Wait for backend to be ready
    $maxRetries = 30
    $retry = 0
    while ($retry -lt $maxRetries) {
        try {
            $response = Invoke-RestMethod -Uri "http://localhost:8000/health" -Method Get -ErrorAction Stop
            if ($response.status -eq "online") {
                Write-Host "    Backend is online!" -ForegroundColor Green
                break
            }
        } catch {
            Start-Sleep -Seconds 1
            $retry++
        }
    }
    
    if ($retry -ge $maxRetries) {
        Write-Host "    [WARNING] Backend health check timeout, but continuing..." -ForegroundColor Yellow
    }
    
    Set-Location $RepoRoot
    Write-Host ""
}

# ============================================
# 3. FRONTEND: Instructions
# ============================================
if (-not $SkipFrontend) {
    Write-Host "[3/3] Frontend (Next.js)..." -ForegroundColor Yellow
    Write-Host "    To start the frontend, run in a separate terminal:" -ForegroundColor Cyan
    Write-Host "      cd $RepoRoot\frontend" -ForegroundColor Gray
    Write-Host "      npm install  # (first time only)" -ForegroundColor Gray
    Write-Host "      npm run dev" -ForegroundColor Gray
    Write-Host ""
}

# ============================================
# Summary
# ============================================
Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "  LAUNCH COMPLETE" -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Backend API:      http://localhost:8000" -ForegroundColor Green
Write-Host "  API Docs:         http://localhost:8000/docs" -ForegroundColor Green
Write-Host "  Blockchain RPC:   http://127.0.0.1:8545" -ForegroundColor Green
Write-Host "  Frontend:         http://localhost:3000 (run 'npm run dev' in frontend/)" -ForegroundColor Green
Write-Host ""
Write-Host "  Press Ctrl+C to stop all background processes" -ForegroundColor Yellow
Write-Host ""

# Keep script alive to maintain background processes
try {
    while ($true) { Start-Sleep -Seconds 10 }
} catch {
    Write-Host "`n[*] Shutting down..." -ForegroundColor Yellow
    if ($hardhatNode) { Stop-Process -Id $hardhatNode.Id -Force -ErrorAction SilentlyContinue }
    if ($backendProcess) { Stop-Process -Id $backendProcess.Id -Force -ErrorAction SilentlyContinue }
    Write-Host "[*] Done." -ForegroundColor Green
}
