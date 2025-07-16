# Database initialization script (init-scripts/01-init-schema.sql)
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

-- Create refresh_tokens table
CREATE TABLE IF NOT EXISTS refresh_tokens (
                                              id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                                              token VARCHAR(255) UNIQUE NOT NULL,
                                              expiry_date TIMESTAMP NOT NULL,
                                              user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                                              created_at TIMESTAMP DEFAULT NOW()
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
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);