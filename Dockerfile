# Dockerfile

# 1) Use a lightweight Python base image
FROM python:3.9-slim

# 2) Set a working directory inside the container
WORKDIR /app

# 3) Copy requirements (if you have a requirements.txt, otherwise skip)
# If you have a requirements.txt, do:
# COPY requirements.txt .
# RUN pip install --no-cache-dir -r requirements.txt

# For now, we assume you might not have a formal requirements.txt. 
# We'll install the basics directly.

RUN pip install requests beautifulsoup4

# 4) Copy the entire project into the container
COPY . .

# 5) By default, the container will run help text if no arguments are given
CMD ["python", "main.py", "--help"]
