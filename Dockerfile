# Use an official Python runtime as the base image
FROM python:3.9-slim

# Set the working directory
WORKDIR /app

# Copy the local code to the container
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port 8002 for the FastAPI app
EXPOSE 8002

# Command to run the FastAPI app using Uvicorn
CMD ["python", "SNMP-Integration.py"]
