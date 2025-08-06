# Multi-stage Dockerfile for API Gateway
# Stage 1: Build the application
FROM amazoncorretto:17-alpine AS builder

WORKDIR /app

# Copy Maven wrapper and pom.xml first for better caching
COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .
COPY donpetre-gateway/pom.xml donpetre-gateway/

# Make mvnw executable
RUN chmod +x mvnw

# Download dependencies (this layer will be cached unless pom.xml changes)
RUN ./mvnw dependency:go-offline -B -f donpetre-gateway/pom.xml

# Copy source code
COPY donpetre-gateway/src donpetre-gateway/src

# Build the application
RUN ./mvnw clean package -DskipTests -B -f donpetre-gateway/pom.xml

# Stage 2: Create the runtime image
FROM amazoncorretto:17-alpine AS runtime

# Add security and operational improvements
RUN apk add --no-cache \
    curl \
    jq \
    && addgroup -S appuser \
    && adduser -S appuser -G appuser

RUN rm -rf /var/lib/apt/lists/* \

WORKDIR /app

# Copy the JAR from builder stage
COPY --from=builder /app/donpetre-gateway/target/donpetre-gateway.jar app.jar

# Create directories for logs and secrets
RUN mkdir -p /app/logs /app/secrets \
    && chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/actuator/health || exit 1

# Expose port
EXPOSE 8080

# JVM optimizations for containerized environments
ENV JAVA_OPTS="-XX:+UseContainerSupport \
               -XX:MaxRAMPercentage=75.0 \
               -XX:+UseG1GC \
               -XX:+UseStringDeduplication \
               -Djava.security.egd=file:/dev/./urandom \
               -Dspring.profiles.active=docker"

# Entry point with proper signal handling
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar app.jar"]