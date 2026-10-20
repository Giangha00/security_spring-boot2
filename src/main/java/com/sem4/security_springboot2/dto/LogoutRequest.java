package com.sem4.security_springboot2.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public record LogoutRequest(
    @Schema(description = "Refresh token cần thu hồi (tùy chọn)")
    String refreshToken
) {}
