package com.sem4.security_springboot2.service;

import com.sem4.security_springboot2.entity.RevokedToken;
import com.sem4.security_springboot2.repository.RevokedTokenRepository;
import com.sem4.security_springboot2.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Service
public class RevocationService {
    private final RevokedTokenRepository revokedTokenRepository;
    private final UserRepository userRepository;

    // Cache of revoked access token JTIs (JTI -> expiresAt)
    private final ConcurrentMap<String, Instant> revokedJtiCache = new ConcurrentHashMap<>();

    // Cache of user tokenVersion & enabled status with max 5s TTL
    private final ConcurrentMap<String, CachedUserStatus> userStatusCache = new ConcurrentHashMap<>();

    public RevocationService(RevokedTokenRepository revokedTokenRepository, UserRepository userRepository) {
        this.revokedTokenRepository = revokedTokenRepository;
        this.userRepository = userRepository;
    }

    @Transactional
    public void revokeAccessToken(String jti, Instant expiresAt) {
        if (jti == null || jti.isBlank()) {
            return;
        }
        Instant exp = expiresAt != null ? expiresAt : Instant.now().plusSeconds(900);
        revokedJtiCache.put(jti, exp);

        if (!revokedTokenRepository.existsByJti(jti)) {
            revokedTokenRepository.save(new RevokedToken(jti, exp));
        }
    }

    public boolean isJtiRevoked(String jti) {
        if (jti == null || jti.isBlank()) {
            return false;
        }

        Instant cachedExp = revokedJtiCache.get(jti);
        if (cachedExp != null) {
            if (Instant.now().isAfter(cachedExp)) {
                revokedJtiCache.remove(jti);
                return false;
            }
            return true;
        }

        boolean existsInDb = revokedTokenRepository.existsByJti(jti);
        if (existsInDb) {
            revokedJtiCache.put(jti, Instant.now().plusSeconds(900));
        }
        return existsInDb;
    }

    public void invalidateUserCache(String username) {
        if (username != null) {
            userStatusCache.remove(username);
        }
    }

    public CachedUserStatus getUserStatus(String username) {
        if (username == null || username.isBlank()) {
            return null;
        }

        Instant now = Instant.now();
        CachedUserStatus cached = userStatusCache.get(username);
        if (cached != null && Duration.between(cached.cachedAt(), now).toMillis() < 5000) {
            return cached;
        }

        return userRepository.findByUsername(username)
            .map(user -> {
                CachedUserStatus fresh = new CachedUserStatus(user.getTokenVersion(), user.isEnabled(), now);
                userStatusCache.put(username, fresh);
                return fresh;
            })
            .orElse(null);
    }

    public record CachedUserStatus(int tokenVersion, boolean enabled, Instant cachedAt) {}
}
