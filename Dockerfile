# Use an official Python runtime as a parent image.
# Debian 11 (bullseye) LTS ended 2026-08-31, so use bookworm (Debian 12).
# Pinned by digest for reproducible builds (tag: 3.12-slim-bookworm).
FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258

# Set the working directory in the container
WORKDIR /app

# Apply OS security updates in a single layer and clean the apt cache
RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies (all have prebuilt cp312 wheels, no compiler needed)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application source (filtered by .dockerignore)
COPY . .

# Expose port 8080 to the outside world
EXPOSE 8080

# Run the app when the container launches
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
