FROM eclipse-temurin:23-jdk-alpine AS builder
LABEL authors="jones"

WORKDIR /build

COPY mvnw pom.xml ./

COPY .mvn .mvn

COPY src src

RUN chmod +x mvnw && ./mvnw clean package -DskipTests


FROM eclipse-temurin:23-jre-alpine
WORKDIR /app

COPY --from=builder /build/target/authorization-server-0.0.1-SNAPSHOT.jar authorization-server.jar


ENTRYPOINT ["java", "-jar", "/authorization-server.jar"]