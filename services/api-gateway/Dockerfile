FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
COPY services/shared/package.json ./services/shared/
COPY services/api-gateway/package.json ./services/api-gateway/
RUN npm ci --workspaces --if-present
COPY services/shared/ ./services/shared/
COPY services/api-gateway/ ./services/api-gateway/
COPY tsconfig.json ./
RUN npm run build --workspace=@apollo/shared
RUN npm run build --workspace=@apollo/api-gateway

FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
COPY services/shared/package.json ./services/shared/
COPY services/api-gateway/package.json ./services/api-gateway/
RUN npm ci --workspaces --if-present --omit=dev
COPY --from=builder /app/services/shared/dist ./services/shared/dist
COPY --from=builder /app/services/api-gateway/dist ./services/api-gateway/dist
RUN mkdir -p /app/logs
ENV NODE_ENV=production
EXPOSE 3000
HEALTHCHECK CMD node -e "require('http').get('http://localhost:3000/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"
CMD ["node", "services/api-gateway/dist/index.js"]
