package com.openrangelabs.donpetre.gateway;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Simple utility to generate BCrypt password hash for "password123"
 * using the same configuration as the application (BCrypt strength 12)
 */
public class PasswordHashGenerator {
    
    public static void main(String[] args) {
        // Use same BCrypt configuration as SecurityConfig
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
        
        String password = "password123";
        String hash = encoder.encode(password);
        
        System.out.println("===== PASSWORD HASH GENERATOR =====");
        System.out.println("Password: " + password);
        System.out.println("BCrypt Hash: " + hash);
        System.out.println("");
        
        // Verify the hash works
        boolean matches = encoder.matches(password, hash);
        System.out.println("Hash verification: " + matches);
        System.out.println("");
        
        // Generate SQL to update all users
        System.out.println("===== SQL UPDATE STATEMENT =====");
        System.out.println("UPDATE users SET password = '" + hash + "';");
        System.out.println("");
        
        System.out.println("===== INSTRUCTIONS =====");
        System.out.println("1. Copy the SQL UPDATE statement above");
        System.out.println("2. Execute it in your PostgreSQL database");
        System.out.println("3. Test authentication with username: admin, password: password123");
    }
}