# Use a slim Python base to keep the initial footprint small
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_APP=run.py \
    FLASK_ENV=development

# Set the working directory
WORKDIR /app

# Install system dependencies
# Combined into one RUN to keep the image layer count low
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Upgrade pip first for better dependency resolution
RUN pip install --no-cache-dir --upgrade pip

# Install CPU-only torch FIRST. 
# This prevents 'sentence-transformers' from pulling the 4GB+ CUDA version later.
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

# Copy only the requirement file first to leverage Docker cache
COPY requirement.txt .

# Install the rest of the dependencies
RUN pip install --no-cache-dir -r requirement.txt

# Copy the rest of your application code
# Putting this AFTER the pip install ensures that changing your code 
# doesn't trigger a full re-install of your 1.5GB of libraries.
COPY . .

# Expose the Flask port
EXPOSE 5000

# Use 'flask run' directly. 
# 0.0.0.0 is critical for accessing the app from outside the container.
CMD ["flask", "run", "--host=0.0.0.0"]