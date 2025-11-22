FROM gradle:8.6-jdk21 AS builder

WORKDIR /workspace
COPY . .

RUN gradle build --no-daemon --quiet

FROM eclipse-temurin:21-jre
EXPOSE 9090

RUN useradd -r -s /bin/false appuser
USER appuser

WORKDIR /app
COPY --from=builder /workspace/build/libs/backend.jar app.jar

ENTRYPOINT ["java", "-jar", "/app/app.jar"]
