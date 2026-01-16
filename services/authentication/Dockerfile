FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY services/shared/package.json ./services/shared/
COPY services/authentication/package.json ./services/authentication/

# Install dependencies
RUN npm install --workspaces --if-present

# Copy source code
COPY services/shared/ ./services/shared/
COPY services/authentication/ ./services/authentication/
COPY tsconfig.json ./

# Build
RUN npm run build --workspace=@apollo/shared
RUN npm run build --workspace=@apollo/authentication

# Production stage
FROM node:20-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY services/shared/package.json ./services/shared/
COPY services/authentication/package.json ./services/authentication/

# Install production dependencies only
RUN npm install --workspaces --if-present --omit=dev

# Copy built files
COPY --from=builder /app/services/shared/dist ./services/shared/dist
COPY --from=builder /app/services/authentication/dist ./services/authentication/dist

# Create logs directory
RUN mkdir -p /app/logs

# Set environment
ENV NODE_ENV=production

# Expose port
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3001/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Start application
CMD ["node", "services/authentication/dist/index.js"]
