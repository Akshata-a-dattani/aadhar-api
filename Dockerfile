FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py encrypt.py ./
COPY templates ./templates
COPY static ./static

CMD ["sh", "-c", "exec gunicorn --bind :${PORT:-8080} --workers 2 --threads 4 app:app"]
