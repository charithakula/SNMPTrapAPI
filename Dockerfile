# Use the official Python image as a base image
FROM python:3.13.2-slim

# Set environment variables to prevent Python from writing pyc files to disk
ENV PYTHONUNBUFFERED 1

# Set a working directory inside the container
WORKDIR /app

# Copy the requirements file to the container
COPY requirements.txt /app/

# Install the Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
COPY . /app/

# Expose the port on which the Flask app will run
EXPOSE 8000

# Set the default command to run the Flask app
CMD ["python", "app.py"]
