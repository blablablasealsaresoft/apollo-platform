#!/bin/bash

# Start all services in development mode

echo "Starting Apollo Backend Services in Development Mode..."
echo ""

# Kill any existing processes on these ports
echo "Cleaning up any existing processes..."
lsof -ti:3000,3001,3002,3003,3004,3005,3006,3007 | xargs kill -9 2>/dev/null || true

# Start services in background
echo "Starting services..."

cd authentication && npm run dev > logs/dev.log 2>&1 &
echo "✓ Authentication Service (3001)"

cd ../user-management && npm run dev > logs/dev.log 2>&1 &
echo "✓ User Management Service (3002)"

cd ../operations && npm run dev > logs/dev.log 2>&1 &
echo "✓ Operations Service (3003)"

cd ../intelligence && npm run dev > logs/dev.log 2>&1 &
echo "✓ Intelligence Service (3004)"

cd ../notifications && npm run dev > logs/dev.log 2>&1 &
echo "✓ Notifications Service (3005)"

cd ../analytics && npm run dev > logs/dev.log 2>&1 &
echo "✓ Analytics Service (3006)"

cd ../search && npm run dev > logs/dev.log 2>&1 &
echo "✓ Search Service (3007)"

cd ../api-gateway && npm run dev > logs/dev.log 2>&1 &
echo "✓ API Gateway (3000)"

cd ..

echo ""
echo "All services started!"
echo "API Gateway: http://localhost:3000"
echo ""
echo "To stop all services: pkill -f ts-node-dev"
