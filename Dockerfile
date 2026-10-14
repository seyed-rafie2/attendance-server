FROM node:20-slim

# برای کامپایل native ماژول better-sqlite3 (در صورت نیاز)
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

# ⬇️ نکته‌ی کلیدی: کپی «همه‌ی» فایل‌های پروژه
COPY . .

ENV NODE_ENV=production
EXPOSE 3000

CMD ["node", "server.js"]
