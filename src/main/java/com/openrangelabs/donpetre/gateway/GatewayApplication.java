package com.openrangelabs.donpetre.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Main application class for DonPetre API Gateway
 * Updated for Spring Boot 3.5.3 compatibility
 */
@SpringBootApplication
@ConfigurationPropertiesScan("com.openrangelabs.donpetre.gateway.config")
public class GatewayApplication {

    public static void main(String[] args) {
        // Enable debug logging for configuration issues
        System.setProperty("logging.level.org.springframework.boot.context.config", "DEBUG");

        try {
            SpringApplication.run(GatewayApplication.class, args);
        } catch (Exception e) {
            System.err.println("Failed to start application: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}