# Use an official Python image
FROM python:3.10

# Set the working directory inside the container
WORKDIR /app

# Copy all project files into the container
COPY . .

# Install dependencies
RUN pip install --upgrade pip
RUN pip install -r requirements.txt || echo "requirements.txt not found, skipping installation"

# Set the default command to run the scanner
CMD ["python", "scanner.py"]
