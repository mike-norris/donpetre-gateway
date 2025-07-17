// src/main/java/com/openrangelabs/donpetre/gateway/config/PropertiesConfiguration.java
package com.openrangelabs.donpetre.gateway.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration class to enable configuration properties
 * Separates @ConfigurationProperties from @Configuration
 */
@Configuration
@EnableConfigurationProperties({
        JwtSecurityProperties.class
})
public class PropertiesConfiguration {
    // This class enables the configuration properties
    // No additional logic needed here
}