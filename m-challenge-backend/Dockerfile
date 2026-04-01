FROM node:20-alpine AS builder
RUN apk add --no-cache openssl openssl-dev
WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .
RUN npx prisma generate
RUN npx tsc

FROM node:20-alpine
RUN apk add --no-cache openssl nmap nmap-scripts sslscan curl unzip
RUN curl -sL "https://github.com/projectdiscovery/naabu/releases/download/v2.3.1/naabu_2.3.1_linux_amd64.zip" -o /tmp/naabu.zip && \
    unzip -o /tmp/naabu.zip -d /tmp/naabu_dir && \
    find /tmp/naabu_dir -name "naabu" -type f -exec mv {} /usr/local/bin/naabu \; && \
    chmod +x /usr/local/bin/naabu && \
    rm -rf /tmp/naabu.zip /tmp/naabu_dir || echo "naabu install optional"
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
