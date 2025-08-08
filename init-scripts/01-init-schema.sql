-- Database initialization script for DonPetre (init-scripts/01-init-schema.sql)
-- Updated for new database name and R2DBC compatibility

-- Create roles table
CREATE TABLE IF NOT EXISTS roles (
                                     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                                     name VARCHAR(50) UNIQUE NOT NULL,
                                     description TEXT
);

-- Create users table
CREATE TABLE IF NOT EXISTS users (
                                     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                                     username VARCHAR(100) UNIQUE NOT NULL,
                                     email VARCHAR(255) UNIQUE NOT NULL,
                                     password VARCHAR(255) NOT NULL,
                                     is_active BOOLEAN DEFAULT true,
                                     created_at TIMESTAMP DEFAULT NOW(),
                                     last_login TIMESTAMP
);

-- Create user_roles junction table
CREATE TABLE IF NOT EXISTS user_roles (
                                          user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                                          role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
                                          PRIMARY KEY (user_id, role_id)
);

-- Create refresh_tokens table (updated for R2DBC)
CREATE TABLE IF NOT EXISTS refresh_tokens (
                                              id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                                              token VARCHAR(512) UNIQUE NOT NULL,
                                              expiry_date TIMESTAMP NOT NULL,
                                              user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                                              created_at TIMESTAMP DEFAULT NOW(),
                                              last_used TIMESTAMP,
                                              device_info VARCHAR(255)
);

-- Insert default roles
INSERT INTO roles (name, description) VALUES
                                          ('ADMIN', 'Administrator role with full system access'),
                                          ('USER', 'Standard user role with basic access'),
                                          ('VIEWER', 'Read-only access to knowledge items')
ON CONFLICT (name) DO NOTHING;

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active);
CREATE INDEX IF NOT EXISTS idx_users_last_login ON users(last_login);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expiry ON refresh_tokens(expiry_date);

CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);

-- Create a default admin user (password: password123 - change in production!)
-- Password is BCrypt hash of "password123"
INSERT INTO users (username, email, password, is_active) VALUES
    ('admin', 'admin@donpetre.com', '$2a$12$.SiNRaCuL/8jt.3i4Kt1hOfRc9shFqfJ8yaBaTcrAvMhYto9FxEDm', true)
ON CONFLICT (username) DO NOTHING;

-- Assign admin role to admin user
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.username = 'admin' AND r.name = 'ADMIN'
ON CONFLICT (user_id, role_id) DO NOTHING;

-- Create a test user (password: user123 - for development only)
INSERT INTO users (username, email, password, is_active) VALUES
    ('testuser', 'test@donpetre.com', '$2a$12$.SiNRaCuL/8jt.3i4Kt1hOfRc9shFqfJ8yaBaTcrAvMhYto9FxEDm', true)
ON CONFLICT (username) DO NOTHING;

-- Assign user role to test user
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.username = 'testuser' AND r.name = 'USER'
ON CONFLICT (user_id, role_id) DO NOTHING;

-- Create knowledge_sources table (referenced by ingestion service)
CREATE TABLE IF NOT EXISTS knowledge_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(50) NOT NULL,
    configuration JSONB NOT NULL,
    last_sync TIMESTAMP,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Create indexes for knowledge_sources
CREATE INDEX IF NOT EXISTS idx_knowledge_sources_type ON knowledge_sources(type);
CREATE INDEX IF NOT EXISTS idx_knowledge_sources_active ON knowledge_sources(is_active);
CREATE INDEX IF NOT EXISTS idx_knowledge_sources_last_sync ON knowledge_sources(last_sync);