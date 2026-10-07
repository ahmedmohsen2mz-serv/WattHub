FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=UTC

# Set working directory
WORKDIR /app

# Copy application files
COPY server.py .
COPY frontend/ ./frontend/

# Create the data directory for persistent storage
RUN mkdir -p /app/.watthub-data

# Expose Web UI and Strip TCP port
EXPOSE 8080 10086

# Start the server
CMD ["python3", "server.py", "serve", "--web-port", "8080", "--port", "10086", "--ip", "0.0.0.0"]
