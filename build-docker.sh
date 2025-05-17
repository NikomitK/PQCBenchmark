#!/usr/bin/bash
# This script builds the Docker image for the project.
# It uses the Dockerfile located in the current directory.
# Usage: ./build-docker.sh
# Check if Docker is installed
if ! command -v docker &> /dev/null
then
    echo "Docker could not be found. Please install Docker to proceed."
    exit 1
fi
# Check if Docker is running
if ! docker info &> /dev/null
then
    echo "Docker is not running. Please start Docker to proceed."
    exit 1
fi
# Build jar file with maven package
mvn clean package -DskipTests
# Check if the build was successful
if [ $? -ne 0 ]; then
    echo "Maven build failed. Please check the output for errors."
    exit 1
fi
# Remove signature files from jar file
zip -d target/PQCBenchmark-1.0-SNAPSHOT.jar 'META-INF/.SF' 'META-INF/.RSA' 'META-INF/*SF'
# Build the Docker image
docker build --platform linux/amd64,linux/arm64 -t nikomitk/pqc-benchmark:latest .
