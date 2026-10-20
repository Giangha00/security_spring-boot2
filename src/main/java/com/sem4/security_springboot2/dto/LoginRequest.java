package com.sem4.security_springboot2.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
    @Schema(example = "admin", description = "Tên đăng nhập")
    @NotBlank(message = "Username không được để trống")
    String username,

    @Schema(example = "Admin#Catalog2026", description = "Mật khẩu")
    @NotBlank(message = "Mật khẩu không được để trống")
    String password
) {}
