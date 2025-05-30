# Use the official Python image from the Docker Hub
FROM python:3.9-slim

# Set environment variables
ENV VIRTUAL_ENV=/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Install dependencies
RUN apt-get update && \
    apt-get install -y python3-venv build-essential && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create and activate virtual environment
RUN python3 -m venv $VIRTUAL_ENV

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirement.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirement.txt

# Copy the rest of the working directory contents into the container at /app
COPY . .

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Define environment variable for Flask
ENV FLASK_APP=run.py
ENV FLASK_ENV=development 

# Run the application
CMD ["flask", "run", "--host=0.0.0.0"]