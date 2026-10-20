package com.sem4.security_springboot2.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

public record RefreshTokenRequest(
    @Schema(description = "Refresh token dạng raw nhận được khi đăng nhập hoặc refresh lần trước")
    @NotBlank(message = "Refresh token không được để trống")
    String refreshToken
) {}
