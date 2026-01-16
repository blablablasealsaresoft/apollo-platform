# Intelligence Fusion Service Dockerfile
# Multi-stage build for optimized production image

# ============================================
# BUILD STAGE
# ============================================
FROM node:20-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache python3 make g++

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Copy shared package (dependency)
COPY ../shared ../shared

# Install dependencies
RUN npm ci

# Copy source code
COPY src ./src

# Build TypeScript
RUN npm run build

# Prune dev dependencies
RUN npm prune --production

# ============================================
# PRODUCTION STAGE
# ============================================
FROM node:20-alpine AS production

WORKDIR /app

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S fusion -u 1001 -G nodejs

# Copy built application
COPY --from=builder --chown=fusion:nodejs /app/dist ./dist
COPY --from=builder --chown=fusion:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=fusion:nodejs /app/package.json ./

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
