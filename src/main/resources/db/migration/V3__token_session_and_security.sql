-- R5 & R6: token_version on users table for revoking all access tokens
ALTER TABLE users ADD COLUMN token_version INT NOT NULL DEFAULT 1;

-- R1, R2, R3: refresh_tokens table storing SHA-256 hash, family_id, expiration, revocation, IP, and User-Agent
CREATE TABLE refresh_tokens (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    token_hash  VARCHAR(64) NOT NULL UNIQUE,
    user_id     BIGINT NOT NULL,
    family_id   VARCHAR(36) NOT NULL,
    expires_at  DATETIME(6) NOT NULL,
    revoked_at  DATETIME(6) NULL,
    ip_address  VARCHAR(45),
    user_agent  VARCHAR(500),
    created_at  DATETIME(6) NOT NULL,
    CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX idx_refresh_tokens_family ON refresh_tokens (family_id);
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens (user_id);

-- R4: revoked_tokens table for access token jti revocation
CREATE TABLE revoked_tokens (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    jti         VARCHAR(36) NOT NULL UNIQUE,
    expires_at  DATETIME(6) NOT NULL,
    revoked_at  DATETIME(6) NOT NULL
);

CREATE INDEX idx_revoked_tokens_jti ON revoked_tokens (jti);
CREATE INDEX idx_revoked_tokens_expires_at ON revoked_tokens (expires_at);
