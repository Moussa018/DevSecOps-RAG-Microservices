FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml .
RUN mvn -q -B dependency:go-offline
COPY src ./src
RUN mvn -q -B package -DskipTests

FROM gcr.io/distroless/java21-debian13:nonroot
WORKDIR /app
COPY --from=build /app/target/gateway-1.0.0.jar app.jar
USER nonroot
EXPOSE 8080
ENTRYPOINT ["java","-XX:MaxRAMPercentage=75","-jar","/app/app.jar"]
