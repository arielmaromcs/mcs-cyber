FROM node:20-alpine AS builder
RUN apk add --no-cache openssl openssl-dev
WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .
RUN npx prisma generate
RUN npx tsc

RUN apk add --no-cache openssl nmap nmap-scripts sslscan curl unzip
# Install naabu for fast port scanning
RUN curl -sL "https://github.com/projectdiscovery/naabu/releases/download/v2.3.1/naabu_2.3.1_linux_amd64.zip" -o /tmp/naabu.zip && unzip -o /tmp/naabu.zip -d /tmp/naabu_dir && mv /tmp/naabu_dir/naabu /usr/local/bin/naabu && chmod +x /usr/local/bin/naabu && rm -rf /tmp/naabu.zip /tmp/naabu_dir || true
RUN curl -sL https://github.com/projectdiscovery/naabu/releases/download/v2.3.1/naabu_2.3.1_linux_amd64.zip -o /tmp/naabu.zip &&     unzip /tmp/naabu.zip -d /tmp &&     mv /tmp/naabu /usr/local/bin/naabu &&     chmod +x /usr/local/bin/naabu &&     rm /tmp/naabu.zip
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
