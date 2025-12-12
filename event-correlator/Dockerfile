# Event Correlation Engine Dockerfile
FROM python:3.11-slim

LABEL maintainer="Security-Enhancement Team"
LABEL description="Lightweight event correlation engine for security monitoring"
LABEL version="1.0.0"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    sqlite3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create necessary directories
RUN mkdir -p /var/log /tmp

# Create non-root user for security
RUN useradd -r -s /bin/false correlator
RUN chown -R correlator:correlator /app /var/log /tmp

# Set permissions
RUN chmod +x correlator.py

# Switch to non-root user
USER correlator

# Expose configuration volume
VOLUME ["/app/config"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import os; exit(0 if os.path.exists('/app/config.yaml') else 1)"

# Default command
CMD ["python3", "correlator.py", "config.yaml"]

# Build arguments for customization
ARG BUILD_DATE
ARG VERSION
ARG REVISION

# Labels for metadata
LABEL org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.version=$VERSION \
      org.label-schema.revision=$REVISION \
      org.label-schema.schema-version="1.0"