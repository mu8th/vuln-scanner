FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend ./backend
COPY frontend ./frontend

EXPOSE 8000

# Bind all interfaces inside the container; docker-compose maps the port to
# the host's loopback only, so the service stays host-local.
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
