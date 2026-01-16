FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
COPY services/shared/package.json ./services/shared/
COPY services/operations/package.json ./services/operations/
RUN npm install --workspaces --if-present --ignore-scripts
COPY services/shared/ ./services/shared/
COPY services/operations/ ./services/operations/
COPY tsconfig.json ./
RUN npm run build --workspace=@apollo/shared
RUN npm run build --workspace=@apollo/operations

FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
COPY services/shared/package.json ./services/shared/
COPY services/operations/package.json ./services/operations/
RUN npm install --workspaces --if-present --omit=dev --ignore-scripts
COPY --from=builder /app/services/shared/dist ./services/shared/dist
COPY --from=builder /app/services/operations/dist ./services/operations/dist
RUN mkdir -p /app/logs
ENV NODE_ENV=production
EXPOSE 3003
HEALTHCHECK CMD node -e "require('http').get('http://localhost:3003/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"
CMD ["node", "services/operations/dist/index.js"]
