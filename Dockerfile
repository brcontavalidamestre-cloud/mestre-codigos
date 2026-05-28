FROM python:3.12-slim

WORKDIR /app

# Dependências de sistema para o Chromium do Playwright
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget gnupg ca-certificates fonts-liberation \
    libasound2 libatk-bridge2.0-0 libatk1.0-0 libatspi2.0-0 \
    libcairo2 libcups2 libdbus-1-3 libdrm2 libexpat1 libgbm1 \
    libglib2.0-0 libnspr4 libnss3 libpango-1.0-0 libx11-6 \
    libxcb1 libxcomposite1 libxdamage1 libxext6 libxfixes3 \
    libxkbcommon0 libxrandr2 libgtk-3-0 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Instalar Chromium do Playwright (apenas chromium para reduzir tamanho)
RUN python -m playwright install chromium --with-deps || python -m playwright install chromium

COPY . .

EXPOSE 8080

CMD ["sh", "-c", "gunicorn app:app --bind 0.0.0.0:${PORT:-8080} --workers 1 --timeout 180"]
