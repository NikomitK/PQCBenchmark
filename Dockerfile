FROM openjdk:21-slim
LABEL authors="niko"

WORKDIR /tmp

COPY target/PQCBenchmark-1.0-SNAPSHOT.jar /tmp/Benchmark.jar

ENTRYPOINT ["java", "-jar", "Benchmark.jar"]