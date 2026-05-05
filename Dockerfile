# Use minimal trusted base image (security best practice)
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Create non-root user (container security)
RUN useradd -m -u 1000 appuser

# Copy and install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py .

# Set ownership to non-root user
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 5000

# Run the application
CMD ["python", "app.py"]
