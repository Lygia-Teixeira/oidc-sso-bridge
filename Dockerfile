# Imagem de exemplo. Fixe o digest da imagem base em uso real.
FROM node:22-bookworm-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

FROM node:22-bookworm-slim
ENV NODE_ENV=production
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src
# Usuario sem privilegios; sistema de arquivos pode ser somente leitura.
USER node
EXPOSE 3000
CMD ["node", "src/index.js"]
