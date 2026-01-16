# Apollo Reporting Service Dockerfile
# Multi-stage build for optimized production image

# Stage 1: Build
FROM node:20-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache python3 make g++ chromium

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Copy shared library
COPY ../shared ./shared/

# Install dependencies
RUN npm install

# Copy source code
COPY src ./src

# Build TypeScript
RUN npm run build

# Stage 2: Production
FROM node:20-alpine AS production

WORKDIR /app

# Install runtime dependencies for puppeteer/chromium
RUN apk add --no-cache \
    chromium \
    nss \
    freetype \
    harfbuzz \
    ca-certificates \
    ttf-freefont \
    font-noto-emoji \
    && rm -rf /var/cache/apk/*

# Set puppeteer environment variables
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser

# Create non-root user
RUN addgroup -g 1001 -S apollo && \
    adduser -S apollo -u 1001 -G apollo

# Copy package files
COPY package*.json ./

# Install production dependencies only
RUN npm install --omit=dev && npm cache clean --force

# Copy built application
COPY --from=builder /app/dist ./dist

# Create reports directory
RUN mkdir -p /tmp/apollo-reports && chown -R apollo:apollo /tmp/apollo-reports

# Set ownership
RUN chown -R apollo:apollo /app

# Switch to non-root user
USER apollo

# Environment variables
ENV NODE_ENV=production \
    PORT=3008 \
    REPORTS_DIR=/tmp/apollo-reports

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3008/health || exit 1

# Expose port
EXPOSE 3008

# Start the service
CMD ["node", "dist/index.js"]
