package com.sem4.security_springboot2.config;

import com.sem4.security_springboot2.service.RevocationService;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

public class JwtRevocationAndVersionValidator implements OAuth2TokenValidator<Jwt> {
    private final RevocationService revocationService;

    public JwtRevocationAndVersionValidator(RevocationService revocationService) {
        this.revocationService = revocationService;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        // 1. Kiểm tra JTI đã bị thu hồi chưa (R4)
        String jti = jwt.getId();
        if (jti != null && revocationService.isJtiRevoked(jti)) {
            return OAuth2TokenValidatorResult.failure(
                new OAuth2Error("invalid_token", "Access token đã bị thu hồi", null)
            );
        }

        // 2. Kiểm tra token_version và trạng thái tài khoản (R5, R6)
        String username = jwt.getSubject();
        if (username != null) {
            RevocationService.CachedUserStatus status = revocationService.getUserStatus(username);
            if (status == null || !status.enabled()) {
                return OAuth2TokenValidatorResult.failure(
                    new OAuth2Error("invalid_token", "Tài khoản người dùng đã bị khóa hoặc không tồn tại", null)
                );
            }

            Object verClaim = jwt.getClaims().get("ver");
            if (verClaim instanceof Number num) {
                int tokenVer = num.intValue();
                if (tokenVer < status.tokenVersion()) {
                    return OAuth2TokenValidatorResult.failure(
                        new OAuth2Error("invalid_token", "Token version không còn hợp lệ do đã đăng xuất hoặc thay đổi mật khẩu", null)
                    );
                }
            }
        }

        return OAuth2TokenValidatorResult.success();
    }
}
