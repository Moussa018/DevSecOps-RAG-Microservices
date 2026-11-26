# Build context: repository root (docker build -f services/uaa-service/Dockerfile .)
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
COPY services services
RUN --mount=type=cache,target=/root/.m2 mvn -q -B -pl services/uaa-service -am -DskipTests package

FROM gcr.io/distroless/java21-debian13:nonroot
COPY --from=build /src/services/uaa-service/target/uaa-service-1.0.0.jar /app/app.jar
USER nonroot
EXPOSE 8000
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/app.jar"]
