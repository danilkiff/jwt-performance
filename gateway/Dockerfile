FROM gradle:9.3.1-jdk25 AS builder

WORKDIR /workspace
COPY . .

RUN gradle build --no-daemon --quiet

FROM eclipse-temurin:25-jre
EXPOSE 9090

RUN useradd -r -s /bin/false appuser
USER appuser

WORKDIR /app
COPY --from=builder /workspace/build/libs/gateway.jar app.jar

ENTRYPOINT ["java", "-jar", "/app/app.jar"]
