FROM node:20-alpine AS builder
RUN apk add --no-cache openssl openssl-dev
WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .
RUN npx prisma generate
RUN npx tsc

FROM node:20-alpine
RUN apk add --no-cache openssl nmap nmap-scripts sslscan
WORKDIR /app

# Copy everything needed at runtime
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/prisma ./prisma
COPY --from=builder /app/package.json ./

# Regenerate Prisma client for runtime platform
RUN npx prisma generate

# Startup script
COPY scripts/start.sh ./start.sh
RUN chmod +x start.sh

EXPOSE 3001
CMD ["./start.sh"]
