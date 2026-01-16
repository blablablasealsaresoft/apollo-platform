# Intelligence Fusion Service Dockerfile
# Multi-stage build for optimized production image

FROM node:20-alpine AS builder
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache python3 make g++

# Copy package files from repo root
COPY package*.json ./
COPY services/shared/package.json ./services/shared/
COPY services/intelligence-fusion/package.json ./services/intelligence-fusion/

# Install dependencies
RUN npm install --workspaces --if-present

# Copy source code
COPY services/shared/ ./services/shared/
COPY services/intelligence-fusion/ ./services/intelligence-fusion/
COPY tsconfig.json ./

# Build
RUN npm run build --workspace=@apollo/shared
RUN npm run build --workspace=@apollo/intelligence-fusion

# Production stage
FROM node:20-alpine

WORKDIR /app

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S fusion -u 1001 -G nodejs

# Copy package files
COPY package*.json ./
COPY services/shared/package.json ./services/shared/
COPY services/intelligence-fusion/package.json ./services/intelligence-fusion/

# Install production dependencies only
RUN npm install --workspaces --if-present --omit=dev

# Copy built files
COPY --from=builder /app/services/shared/dist ./services/shared/dist
COPY --from=builder /app/services/intelligence-fusion/dist ./services/intelligence-fusion/dist

# Create logs directory
RUN mkdir -p /app/logs && chown -R fusion:nodejs /app

# Set environment
ENV NODE_ENV=production
ENV FUSION_SERVICE_PORT=3008

# Expose port
EXPOSE 3008

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3008/health || exit 1

# Switch to non-root user
USER fusion

# Start application
CMD ["node", "services/intelligence-fusion/dist/index.js"]
