//package com.openrangelabs.donpetre.gateway.config;
//
//import io.r2dbc.postgresql.PostgresqlConnectionConfiguration;
//import io.r2dbc.postgresql.PostgresqlConnectionFactory;
//import io.r2dbc.spi.ConnectionFactory;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.data.r2dbc.config.AbstractR2dbcConfiguration;
//import org.springframework.data.r2dbc.repository.config.EnableR2dbcRepositories;
//import org.springframework.r2dbc.connection.R2dbcTransactionManager;
//import org.springframework.transaction.ReactiveTransactionManager;
//
///**
// * R2DBC Configuration for reactive database operations
// * Replaces JPA configuration for non-blocking database access
// */
//@Configuration
//@EnableR2dbcRepositories(basePackages = "com.openrangelabs.donpetre.gateway.repository")
//public class R2dbcConfig extends AbstractR2dbcConfiguration {
//
//    @Value("${spring.r2dbc.host:localhost}")
//    private String host;
//
//    @Value("${spring.r2dbc.port:5432}")
//    private int port;
//
//    @Value("${spring.r2dbc.database:donpetre}")
//    private String database;
//
//    @Value("${spring.r2dbc.username:don}")
//    private String username;
//
//    @Value("${spring.r2dbc.password:don_pass}")
//    private String password;
//
//    @Override
//    @Bean
//    public ConnectionFactory connectionFactory() {
//        log.info("R2DBC connection factory "+username+"::"+password+" "+host+":"+port+"/"+database);
//        return new PostgresqlConnectionFactory(
//                PostgresqlConnectionConfiguration.builder()
//                        .host(host)
//                        .port(port)
//                        .database(database)
//                        .username(username)
//                        .password(password)
//                        .build()
//        );
//    }
//
//    @Bean
//    public ReactiveTransactionManager transactionManager(ConnectionFactory connectionFactory) {
//        return new R2dbcTransactionManager(connectionFactory);
//    }
//}