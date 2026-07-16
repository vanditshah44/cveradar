FROM python:3.12-slim

WORKDIR /app

# Install system deps needed by psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# In dev, the entire ./backend dir is bind-mounted over /app
# so this COPY is mainly for production builds
COPY . .

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
