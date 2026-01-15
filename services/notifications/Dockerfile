FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
COPY services/shared/package.json ./services/shared/
COPY services/notifications/package.json ./services/notifications/
RUN npm ci --workspaces --if-present
COPY services/shared/ ./services/shared/
COPY services/notifications/ ./services/notifications/
COPY tsconfig.json ./
RUN npm run build --workspace=@apollo/shared
RUN npm run build --workspace=@apollo/notifications

FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
COPY services/shared/package.json ./services/shared/
COPY services/notifications/package.json ./services/notifications/
RUN npm ci --workspaces --if-present --omit=dev
COPY --from=builder /app/services/shared/dist ./services/shared/dist
COPY --from=builder /app/services/notifications/dist ./services/notifications/dist
RUN mkdir -p /app/logs
ENV NODE_ENV=production
EXPOSE 3005
HEALTHCHECK CMD node -e "require('http').get('http://localhost:3005/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"
CMD ["node", "services/notifications/dist/index.js"]
