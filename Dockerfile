FROM eclipse-temurin:19-jdk AS base
RUN apt-get update & apt upgrade -y
WORKDIR /app
EXPOSE 80
EXPOSE 443
EXPOSE 9000

FROM eclipse-temurin:19-jdk AS builder
WORKDIR /app
COPY . .
RUN apt-get update && apt -y upgrade && apt-get install -y maven && mvn -DskipTests -Dspring.profiles.active=develop clean package

FROM base AS final
RUN groupadd authserver && useradd -g authserver authserver
USER authserver
WORKDIR /app
COPY --from=builder /app/target/*.jar .
CMD ["java", "-jar", "/app/AuthServerDemo-1.0.0.jar", "--spring.profiles.active=develop"]