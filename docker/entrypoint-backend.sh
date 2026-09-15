#!/bin/bash
# Entrypoint script for backend container
# Waits for PostgreSQL, runs migrations, then starts uvicorn

set -e

echo "=== SIH26106 Backend Entrypoint ==="

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL at ${DATABASE_URL}..."
until pg_isready -h postgres -p 5432 -U "${POSTGRES_USER:-forensics}" -d "${POSTGRES_DB:-sih26106}" > /dev/null 2>&1; do
    echo "PostgreSQL not ready yet, waiting..."
    sleep 2
done
echo "PostgreSQL is ready!"

# Wait for Redis to be ready
echo "Waiting for Redis at redis:6379..."
until redis-cli -h redis -p 6379 ping > /dev/null 2>&1; do
    echo "Redis not ready yet, waiting..."
    sleep 1
done
echo "Redis is ready!"

# Run database migrations
echo "Running database migrations..."
python -c "
import asyncio
import sys
sys.path.insert(0, '/app')
from backend.database import init_db

async def run_migrations():
    init_db()
    print('Migrations completed successfully!')

asyncio.run(run_migrations())
"

# Start the application
echo "Starting uvicorn server..."
exec python -m uvicorn main:app --host 0.0.0.0 --port 8000
