# SIH26106 Forensics - Docker Deployment Guide

## Overview

This directory contains Docker configuration for running the SIH26106 Forensics stack with:
- **PostgreSQL 16** - Primary database (containerized)
- **Redis 7** - Caching and session storage (containerized)
- **Backend API** - FastAPI application (containerized)
- **Frontend** - Next.js application (containerized, served via nginx)
- **Ollama** - Local LLM inference (runs on HOST, not containerized)
- **Hardhat** - Local blockchain node (runs on HOST, not containerized)

## Prerequisites

### Required Software

1. **Docker Desktop** (Windows/Mac) or **Docker Engine + Docker Compose** (Linux)
   - Version 24.0+ recommended
   - WSL2 backend on Windows

2. **Ollama** (on host machine)
   ```bash
   # Install Ollama
   # Windows: Download from https://ollama.ai
   # Linux: curl -fsSL https://ollama.ai/install.sh | sh
   
   # Start Ollama service
   ollama serve
   
   # Pull required model (in another terminal)
   ollama pull llama3.2:3b
   ```

3. **Hardhat** (on host machine, for blockchain features)
   ```bash
   # From project root
   cd blockchain
   npm install
   npx hardhat node
   ```

### Hardware Requirements

- **RAM**: 8GB minimum (16GB recommended for Ollama + containers)
- **GPU**: NVIDIA GPU with CUDA support for Ollama acceleration (RTX 5050 supported)
- **Disk**: 10GB free space

## Quick Start

### 1. Clone and Configure

```bash
git clone <repo-url>
cd SIH26106
```

### 2. Run Preflight Checks

```powershell
# Windows PowerShell
.\scripts\preflight.ps1
```

This verifies Ollama and Hardhat are running on host.

### 3. Launch Stack

```powershell
# Development (with auto-build)
.\scripts\docker-launch.ps1 --build

# Production (detached)
.\scripts\docker-launch.ps1 --build --detach

# Skip preflight (if already verified)
.\scripts\docker-launch.ps1 --no-preflight
```

### 4. Access Services

| Service | URL |
|---------|-----|
| Frontend | http://localhost:3000 |
| Backend API | http://localhost:8000 |
| API Documentation | http://localhost:8000/docs |
| PostgreSQL | localhost:5432 |
| Redis | localhost:6379 |

## Configuration

### Environment Files

| File | Purpose |
|------|---------|
| `docker/.env` | Backend & database configuration |
| `docker/.env.frontend` | Frontend configuration |
| `docker/.env.example` | Template with all options |

### Key Settings

**Database** (`docker/.env`):
```env
POSTGRES_DB=sih26106
POSTGRES_USER=forensics
POSTGRES_PASSWORD=secure_password_here
DATABASE_URL=postgresql+asyncpg://forensics:secure_password_here@postgres:5432/sih26106
```

**Ollama** (host.docker.internal):
```env
OLLAMA_HOST=http://host.docker.internal:11434
```

**Frontend** (`docker/.env.frontend`):
```env
NEXT_PUBLIC_API_URL=http://backend:8000
NEXT_PUBLIC_USE_MOCK=false
```

### Security Notes

⚠️ **CHANGE DEFAULT PASSWORDS** in `.env` before production use!

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        HOST MACHINE                          │
│  ┌──────────────┐    ┌──────────────┐                       │
│  │   Ollama     │    │   Hardhat    │                       │
│  │  :11434      │    │  :8545       │                       │
│  └──────┬───────┘    └──────┬───────┘                       │
│         │                   │                                │
│         ▼                   ▼                                │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              DOCKER NETWORK (bridge)                 │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐           │    │
│  │  │ Postgres │  │  Redis   │  │ Backend  │           │    │
│  │  │  :5432   │  │  :6379   │  │  :8000   │           │    │
│  │  └──────────┘  └──────────┘  └────┬─────┘           │    │
│  │                                    │                 │    │
│  │                         ┌──────────┴──────────┐      │    │
│  │                         │     Frontend        │      │    │
│  │                         │     (nginx:3000)    │      │    │
│  │                         └─────────────────────┘      │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Service Details

### Backend (FastAPI)

- **Port**: 8000
- **Health Check**: `GET /health`
- **API Docs**: `GET /docs` (Swagger UI)
- **Key Endpoints**:
  - `POST /analyze` - Analyze email file
  - `GET /cases` - List cases
  - `GET /cases/{id}` - Get case details
  - `POST /blockchain/anchor` - Anchor to blockchain

### Frontend (Next.js + nginx)

- **Port**: 3000
- **Health Check**: `GET /health`
- **Proxy**: Routes `/api/*` to backend
- **Static Assets**: Served directly by nginx

### PostgreSQL

- **Port**: 5432 (internal), 5432 (host mapping)
- **Database**: `sih26106`
- **User**: `forensics`
- **Data Persistence**: `postgres_data` volume

### Redis

- **Port**: 6379 (internal), 6379 (host mapping)
- **Persistence**: AOF enabled
- **Memory Limit**: 256MB with LRU eviction

## Database Schema

Key tables:
- `cases` - Case metadata with risk scoring
- `evidence` - Cryptographic evidence records (SHA-256)
- `analysis` - JSONB analysis reports with GIN index
- `custody_log` - Chain of custody audit trail
- `schema_migrations` - Migration version tracking

## Common Operations

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend
docker-compose logs -f frontend
docker-compose logs -f postgres
```

### Database Access

```bash
# Connect via psql
docker exec -it sih26106-postgres psql -U forensics -d sih26106

# Run migration manually
docker exec -it sih26106-backend python -c "
import asyncio
from backend.database import init_db
asyncio.run(init_db())
"
```

### Restart Services

```bash
# Restart single service
docker-compose restart backend

# Rebuild and restart
docker-compose up -d --build backend
```

### Backup Database

```bash
# Create backup
docker exec sih26106-postgres pg_dump -U forensics sih26106 > backup_$(date +%Y%m%d).sql

# Restore backup
cat backup_20260915.sql | docker exec -i sih26106-postgres psql -U forensics sih26106
```

## Troubleshooting

### Preflight Fails

**Ollama not running:**
```bash
# Start Ollama
ollama serve

# Verify
curl http://localhost:11434/api/tags
```

**Hardhat not running:**
```bash
cd blockchain
npx hardhat node
```

**Model not found:**
```bash
ollama pull llama3.2:3b
```

### Container Won't Start

**Backend fails health check:**
```bash
# Check backend logs
docker-compose logs backend

# Common issues:
# - DATABASE_URL incorrect in .env
# - PostgreSQL not ready (wait longer)
# - Missing dependencies (rebuild: docker-compose build backend)
```

**Frontend shows 502 Bad Gateway:**
```bash
# Check if backend is healthy
curl http://localhost:8000/health

# Check nginx config
docker exec sih26106-frontend nginx -t
```

**Port conflicts:**
```bash
# Check what's using ports
netstat -tulpn | grep -E '3000|8000|5432|6379'

# Change ports in docker-compose.yml if needed
```

### Database Issues

**Connection refused:**
- Verify postgres container is healthy: `docker-compose ps`
- Check DATABASE_URL format in .env
- Ensure postgres port 5432 not blocked

**Migration errors:**
```bash
# Reset database (DESTROYS DATA)
docker-compose down -v
docker-compose up -d postgres
# Wait for healthy, then start backend
docker-compose up -d backend
```

### Performance

**Slow queries:**
- Check indexes: `\d+` in psql
- Analyze query plans: `EXPLAIN ANALYZE ...`
- Increase PostgreSQL `work_mem` in postgresql.conf

**Ollama slow:**
- Ensure GPU acceleration: `ollama serve` shows GPU info
- Reduce model size: use `llama3.2:1b` for testing
- Increase timeout in backend LLM service

## Development Workflow

### Local Development (without Docker)

```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Frontend
cd frontend
npm install
npm run dev

# Database (SQLite fallback)
# Set DATABASE_URL=sqlite+aiosqlite:///./local.db
```

### Hybrid Mode (DB in Docker, Backend on Host)

```bash
# Start only postgres + redis
docker-compose up -d postgres redis

# Run backend locally with Docker DB
export DATABASE_URL=postgresql+asyncpg://forensics:dev_password@localhost:5432/sih26106
cd backend && uvicorn main:app --reload
```

## Stopping and Cleanup

```bash
# Stop services (keep data)
.\scripts\docker-stop.ps1

# Stop and remove volumes (DESTROYS DATABASE)
.\scripts\docker-stop.ps1 -RemoveVolumes

# Full cleanup including images
.\scripts\docker-stop.ps1 -RemoveVolumes -RemoveImages
```

## CI/CD Integration

For automated deployments:

```yaml
# Example GitHub Actions step
- name: Deploy to Docker
  run: |
    cp docker/.env.example docker/.env
    # Set secrets via GitHub Actions secrets
    echo "POSTGRES_PASSWORD=${{ secrets.POSTGRES_PASSWORD }}" >> docker/.env
    ./scripts/docker-launch.ps1 --build --detach --no-preflight
```

## Support

- Check logs first: `docker-compose logs -f [service]`
- Verify preflight: `.\scripts\preflight.ps1`
- Review this guide for common issues
- Open issue in repository for bugs

## License

Part of SIH26106 Forensics project.
