FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
COPY services/shared/package.json ./services/shared/
COPY services/user-management/package.json ./services/user-management/
RUN npm ci --workspaces --if-present
COPY services/shared/ ./services/shared/
COPY services/user-management/ ./services/user-management/
COPY tsconfig.json ./
RUN npm run build --workspace=@apollo/shared
RUN npm run build --workspace=@apollo/user-management

FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
COPY services/shared/package.json ./services/shared/
COPY services/user-management/package.json ./services/user-management/
RUN npm ci --workspaces --if-present --omit=dev
COPY --from=builder /app/services/shared/dist ./services/shared/dist
COPY --from=builder /app/services/user-management/dist ./services/user-management/dist
RUN mkdir -p /app/logs
ENV NODE_ENV=production
EXPOSE 3002
HEALTHCHECK --interval=30s --timeout=3s CMD node -e "require('http').get('http://localhost:3002/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"
CMD ["node", "services/user-management/dist/index.js"]
