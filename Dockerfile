# AKAGAMI - Advanced Cybersecurity Toolkit
# Multi-stage Docker build for production deployment

FROM node:18-alpine AS frontend-builder

# Set working directory for frontend build
WORKDIR /app/frontend

# Copy package files
COPY frontend/package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy frontend source
COPY frontend/ ./

# Build frontend
RUN npm run build

# Python backend stage
FROM python:3.11-slim

# Set metadata
LABEL maintainer="Security Research Team"
LABEL description="AKAGAMI - Advanced Cybersecurity Penetration Testing Toolkit"
LABEL version="1.0.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV AKAGAMI_ENV=production

# Create non-root user for security
RUN groupadd -r akagami && useradd -r -g akagami akagami

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source code
COPY backend/ ./backend/

# Copy frontend build from previous stage
COPY --from=frontend-builder /app/frontend/build ./frontend/build

# Copy additional files
COPY *.html ./
COPY *.md ./
COPY *.json ./

# Create necessary directories
RUN mkdir -p /app/backend/logs /app/backend/reports /app/backend/uploads /app/backend/data

# Set permissions
RUN chown -R akagami:akagami /app

# Switch to non-root user
USER akagami

# Expose ports
EXPOSE 8001 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

# Default command - start backend server
CMD ["python", "backend/main_simple.py"]
