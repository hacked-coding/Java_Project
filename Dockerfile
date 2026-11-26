FROM eclipse-temurin:21-jdk-alpine
WORKDIR /app
COPY config ./config
COPY src ./src
RUN mkdir -p bin && javac -d bin src/com/honeypot/exception/*.java src/com/honeypot/model/*.java src/com/honeypot/io/*.java src/com/honeypot/network/*.java src/com/honeypot/app/*.java
EXPOSE 8000
CMD ["java", "-cp", "bin", "com.honeypot.app.WebDashboardApp", "config/honeypot.properties"]