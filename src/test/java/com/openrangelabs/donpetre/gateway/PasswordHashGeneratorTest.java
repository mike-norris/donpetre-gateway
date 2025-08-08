package com.openrangelabs.donpetre.gateway;

import com.openrangelabs.donpetre.gateway.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.TestPropertySource;
import reactor.test.StepVerifier;

/**
 * Test to generate BCrypt password hash using Spring Security configuration
 * and update all users in the database with the new hash for "password123"
 */
@Slf4j
@SpringBootTest
@TestPropertySource(properties = {
    "spring.r2dbc.url=r2dbc:postgresql://localhost:5432/donpetre",
    "spring.r2dbc.username=donpetre",
    "spring.r2dbc.password=P1TKDbaP1UdpgiLL",
    "logging.level.com.openrangelabs.donpetre=DEBUG"
})
public class PasswordHashGeneratorTest {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepository;

    @Test
    public void generateAndUpdatePasswordHashes() {
        String newPassword = "password123";
        
        // Generate BCrypt hash using Spring Security configuration
        String newPasswordHash = passwordEncoder.encode(newPassword);
        log.info("Generated BCrypt hash for '{}': {}", newPassword, newPasswordHash);
        
        // Verify the hash works
        boolean matches = passwordEncoder.matches(newPassword, newPasswordHash);
        log.info("Hash verification for '{}': {}", newPassword, matches);
        
        if (!matches) {
            throw new RuntimeException("Generated hash does not match password!");
        }
        
        // Find all users and update their passwords
        StepVerifier.create(
            userRepository.findAll()
                .doOnNext(user -> log.info("Found user: {} with email: {}", user.getUsername(), user.getEmail()))
                .flatMap(user -> {
                    log.info("Updating password for user: {}", user.getUsername());
                    user.setPassword(newPasswordHash);
                    return userRepository.save(user);
                })
                .doOnNext(user -> log.info("Updated password for user: {}", user.getUsername()))
                .count()
        )
        .expectNext(3L) // Expecting 3 users (admin, user1, test_user)
        .verifyComplete();
        
        log.info("Successfully updated all user passwords to hash for: {}", newPassword);
        
        // Verify by loading users and checking password hash
        StepVerifier.create(
            userRepository.findAll()
                .doOnNext(user -> {
                    log.info("Verifying user {}: hash starts with {}", 
                        user.getUsername(), 
                        user.getPassword().substring(0, 20) + "...");
                    boolean hashMatches = passwordEncoder.matches(newPassword, user.getPassword());
                    log.info("Password verification for {}: {}", user.getUsername(), hashMatches);
                })
        )
        .expectNextCount(3)
        .verifyComplete();
        
        log.info("Password hash update and verification completed successfully!");
    }
}