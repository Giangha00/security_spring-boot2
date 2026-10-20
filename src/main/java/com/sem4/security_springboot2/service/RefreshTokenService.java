package com.sem4.security_springboot2.service;

import com.sem4.security_springboot2.dto.TokenResponse;
import com.sem4.security_springboot2.entity.RefreshToken;
import com.sem4.security_springboot2.entity.User;
import com.sem4.security_springboot2.exception.RefreshTokenReusedException;
import com.sem4.security_springboot2.repository.RefreshTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

@Service
public class RefreshTokenService {
    private static final Logger log = LoggerFactory.getLogger(RefreshTokenService.class);
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenService tokenService;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository,
                               TokenService tokenService) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.tokenService = tokenService;
    }

    public String generateSecureRandomToken() {
        byte[] randomBytes = new byte[32]; // 256 bits
        SECURE_RANDOM.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    public String hashToken(String rawToken) {
        if (rawToken == null) {
            return "";
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm unavailable", e);
        }
    }

    @Transactional
    public String createRefreshToken(User user, String ipAddress, String userAgent) {
        String rawToken = generateSecureRandomToken();
        String tokenHash = hashToken(rawToken);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setTokenHash(tokenHash);
        refreshToken.setUser(user);
        refreshToken.setFamilyId(UUID.randomUUID().toString());
        refreshToken.setExpiresAt(Instant.now().plus(7, ChronoUnit.DAYS));
        refreshToken.setRevokedAt(null);
        refreshToken.setIpAddress(ipAddress);
        refreshToken.setUserAgent(userAgent);
        refreshToken.setCreatedAt(Instant.now());

        refreshTokenRepository.save(refreshToken);
        return rawToken;
    }

    @Transactional(noRollbackFor = RefreshTokenReusedException.class)
    public TokenResponse rotateRefreshToken(String rawRefreshToken, String ipAddress, String userAgent) {
        String tokenHash = hashToken(rawRefreshToken);
        RefreshToken token = refreshTokenRepository.findByTokenHash(tokenHash)
            .orElseThrow(() -> new BadCredentialsException("Refresh token không hợp lệ"));

        // Constant-time hash verification
        byte[] storedHashBytes = token.getTokenHash().getBytes(StandardCharsets.UTF_8);
        byte[] inputHashBytes = tokenHash.getBytes(StandardCharsets.UTF_8);
        if (!MessageDigest.isEqual(storedHashBytes, inputHashBytes)) {
            throw new BadCredentialsException("Refresh token không hợp lệ");
        }

        if (token.isExpired()) {
            throw new BadCredentialsException("Refresh token đã hết hạn");
        }

        // R3: Reuse detection
        if (token.isRevoked()) {
            log.warn("Refresh token reuse detected for family_id={}! Revoking all tokens in family.", token.getFamilyId());
            refreshTokenRepository.revokeAllByFamilyId(token.getFamilyId(), Instant.now());
            throw new RefreshTokenReusedException("REFRESH_TOKEN_REUSED");
        }

        // Mark old token as used/revoked
        token.setRevokedAt(Instant.now());
        refreshTokenRepository.save(token);

        // Issue new refresh token in the same family
        String newRawToken = generateSecureRandomToken();
        String newTokenHash = hashToken(newRawToken);

        RefreshToken newToken = new RefreshToken();
        newToken.setTokenHash(newTokenHash);
        newToken.setUser(token.getUser());
        newToken.setFamilyId(token.getFamilyId());
        newToken.setExpiresAt(Instant.now().plus(7, ChronoUnit.DAYS));
        newToken.setRevokedAt(null);
        newToken.setIpAddress(ipAddress);
        newToken.setUserAgent(userAgent);
        newToken.setCreatedAt(Instant.now());
        refreshTokenRepository.save(newToken);

        // Issue new access token
        String accessToken = tokenService.issueAccessToken(token.getUser());
        return new TokenResponse(accessToken, "Bearer", tokenService.getTtl().toSeconds(), newRawToken);
    }

    @Transactional
    public void revokeToken(String rawRefreshToken) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            return;
        }
        String tokenHash = hashToken(rawRefreshToken);
        refreshTokenRepository.findByTokenHash(tokenHash).ifPresent(token -> {
            if (token.getRevokedAt() == null) {
                token.setRevokedAt(Instant.now());
                refreshTokenRepository.save(token);
            }
        });
    }

    @Transactional
    public void revokeAllForUser(Long userId) {
        if (userId != null) {
            refreshTokenRepository.revokeAllByUserId(userId, Instant.now());
        }
    }
}
