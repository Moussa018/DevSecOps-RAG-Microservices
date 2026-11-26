# Build context: repository root (docker build -f services/gateway/Dockerfile .)
FROM maven:3.9-eclipse-temurin-26 AS build
WORKDIR /src
COPY pom.xml .
COPY services services
RUN --mount=type=cache,target=/root/.m2 mvn -q -B -pl services/gateway -am -DskipTests package

FROM gcr.io/distroless/java21-debian13:nonroot
COPY --from=build /src/services/gateway/target/gateway-1.0.0.jar /app/app.jar
USER nonroot
EXPOSE 8080
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/app.jar"]
