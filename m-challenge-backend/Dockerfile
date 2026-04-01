FROM node:20-alpine AS builder
RUN apk add --no-cache openssl openssl-dev
WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .
RUN npx prisma generate
RUN npx tsc

FROM node:20-alpine
RUN apk add --no-cache openssl nmap nmap-scripts sslscan curl unzip wget
# Install naabu
RUN wget -q "https://github.com/projectdiscovery/naabu/releases/download/v2.3.1/naabu_2.3.1_linux_amd64.zip" -O /tmp/naabu.zip 2>/dev/null && \
    unzip -o /tmp/naabu.zip naabu -d /usr/local/bin/ 2>/dev/null && \
    chmod +x /usr/local/bin/naabu && \
    rm -f /tmp/naabu.zip && \
    echo "naabu installed: $(naabu -version 2>&1 | head -1)" || echo "naabu install skipped"
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/prisma ./prisma
COPY --from=builder /app/package.json ./
RUN npx prisma generate
COPY scripts/start.sh ./start.sh
RUN chmod +x start.sh
EXPOSE 3001
CMD ["./start.sh"]
