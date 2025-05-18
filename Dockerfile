FROM openjdk:21-slim
LABEL authors="niko"

ARG REPETITIONS=50
ARG SECURITY_LEVEL=1

WORKDIR /tmp

COPY target/PQCBenchmark-1.0-SNAPSHOT.jar /tmp/Benchmark.jar

ENTRYPOINT ["java", "-jar", "/tmp/Benchmark.jar", "-r", "${REPETITIONS}", "-s", "${SECURITY_LEVEL}"]