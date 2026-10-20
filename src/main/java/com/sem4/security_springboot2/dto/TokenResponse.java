package com.sem4.security_springboot2.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public record TokenResponse(
    @Schema(description = "JWT dùng trong header Authorization")
    String accessToken,

    @Schema(example = "Bearer", description = "Loại token")
    String tokenType,

    @Schema(description = "Số giây còn hiệu lực", example = "900")
    long expiresIn,

    @Schema(description = "Refresh token 256-bit ngẫu nhiên dùng để cấp lại access token mới")
    String refreshToken
) {
    public TokenResponse(String accessToken, String tokenType, long expiresIn) {
        this(accessToken, tokenType, expiresIn, null);
    }
}
