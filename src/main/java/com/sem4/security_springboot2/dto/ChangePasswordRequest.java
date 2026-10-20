package com.sem4.security_springboot2.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ChangePasswordRequest(
    @Schema(example = "Admin#Catalog2026", description = "Mật khẩu hiện tại")
    @NotBlank(message = "Mật khẩu hiện tại không được để trống")
    String currentPassword,

    @Schema(example = "NewAdmin#Password2026", description = "Mật khẩu mới")
    @NotBlank(message = "Mật khẩu mới không được để trống")
    @Size(min = 6, message = "Mật khẩu mới tối thiểu 6 ký tự")
    String newPassword
) {}
