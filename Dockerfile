FROM maven:3.8.4-openjdk-17 AS builder

# Copy the entire project to the container
COPY pom.xml /pom.xml
COPY src /src

# Package our application code
RUN mvn clean install

# The second stage of our build will use OpenJDK 17 on a slim image
FROM maven:3.8.4-openjdk-17

# Copy only the JAR from the first stage and discard the rest
COPY --from=builder /target/*.jar /output/backend_springboot.jar

# Expose port 8080
EXPOSE 8080

# Set the startup command to execute the jar
CMD ["java", "-jar", "/output/backend_springboot.jar"]

