package com.sem4.security_springboot2.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Entity
@Table(name = "revoked_tokens", indexes = {
    @Index(name = "idx_revoked_tokens_jti", columnList = "jti"),
    @Index(name = "idx_revoked_tokens_expires_at", columnList = "expires_at")
})
@Getter
@Setter
@NoArgsConstructor
public class RevokedToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 36)
    private String jti;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "revoked_at", nullable = false)
    private Instant revokedAt = Instant.now();

    public RevokedToken(String jti, Instant expiresAt) {
        this.jti = jti;
        this.expiresAt = expiresAt;
        this.revokedAt = Instant.now();
    }
}
