package com.sem4.security_springboot2.service;

import com.sem4.security_springboot2.repository.RefreshTokenRepository;
import com.sem4.security_springboot2.repository.RevokedTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Component
public class CleanupJob {
    private static final Logger log = LoggerFactory.getLogger(CleanupJob.class);

    private final RefreshTokenRepository refreshTokenRepository;
    private final RevokedTokenRepository revokedTokenRepository;

    public CleanupJob(RefreshTokenRepository refreshTokenRepository,
                      RevokedTokenRepository revokedTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.revokedTokenRepository = revokedTokenRepository;
    }

    // Dọn dẹp định kỳ mỗi ngày lúc 03:00 sáng
    @Scheduled(cron = "0 0 3 * * ?")
    @Transactional
    public void cleanupExpiredTokens() {
        Instant now = Instant.now();
        int deletedRefresh = refreshTokenRepository.deleteExpiredTokens(now);
        int deletedRevoked = revokedTokenRepository.deleteExpiredTokens(now);
        log.info("Dọn dẹp token hết hạn hoàn tất: {} refresh tokens, {} revoked access tokens", deletedRefresh, deletedRevoked);
    }
}
