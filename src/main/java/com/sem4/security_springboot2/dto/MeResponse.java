package com.sem4.security_springboot2.dto;

import io.swagger.v3.oas.annotations.media.Schema;

import java.time.Instant;
import java.util.List;

public record MeResponse(
    @Schema(description = "Tên đăng nhập", example = "admin")
    String username,

    @Schema(description = "Danh sách vai trò", example = "[\"ROLE_USER\", \"ROLE_ADMIN\"]")
    List<String> roles,

    @Schema(description = "Thời điểm hết hạn của access token")
    Instant expiresAt
) {}
