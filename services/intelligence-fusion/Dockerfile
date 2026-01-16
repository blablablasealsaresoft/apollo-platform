# Intelligence Fusion Service Dockerfile
# Multi-stage build for optimized production image

# ============================================
# BUILD STAGE
# ============================================
FROM node:20-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache python3 make g++

# Copy package files from repo root
COPY package*.json ./
COPY tsconfig.json ./

# Copy shared package (dependency)
COPY services/shared ./services/shared

# Copy service-specific files
COPY services/intelligence-fusion/package*.json ./services/intelligence-fusion/
COPY services/intelligence-fusion/tsconfig.json ./services/intelligence-fusion/

# Install dependencies
RUN npm install --workspaces --if-present

# Copy source code
COPY services/intelligence-fusion/src ./services/intelligence-fusion/src

# Build TypeScript
RUN npm run build --workspace=@apollo/shared || true
RUN npm run build --workspace=services/intelligence-fusion || cd services/intelligence-fusion && npm run build || true

# ============================================
# PRODUCTION STAGE
# ============================================
FROM node:20-alpine AS production

WORKDIR /app

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S fusion -u 1001 -G nodejs

# Copy built application
COPY --from=builder --chown=fusion:nodejs /app/services/intelligence-fusion/dist ./dist
COPY --from=builder --chown=fusion:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=fusion:nodejs /app/services/intelligence-fusion/package.json ./

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
CMD ["node", "dist/index.js"]
