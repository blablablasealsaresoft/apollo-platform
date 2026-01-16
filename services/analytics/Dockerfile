FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
COPY services/shared/package.json ./services/shared/
COPY services/analytics/package.json ./services/analytics/
RUN npm install --workspaces --if-present
COPY services/shared/ ./services/shared/
COPY services/analytics/ ./services/analytics/
COPY tsconfig.json ./
RUN npm run build --workspace=@apollo/shared
RUN npm run build --workspace=@apollo/analytics

FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
COPY services/shared/package.json ./services/shared/
COPY services/analytics/package.json ./services/analytics/
RUN npm install --workspaces --if-present --omit=dev
COPY --from=builder /app/services/shared/dist ./services/shared/dist
COPY --from=builder /app/services/analytics/dist ./services/analytics/dist
RUN mkdir -p /app/logs
ENV NODE_ENV=production
EXPOSE 3006
HEALTHCHECK CMD node -e "require('http').get('http://localhost:3006/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"
CMD ["node", "services/analytics/dist/index.js"]
