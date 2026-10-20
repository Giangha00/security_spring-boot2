package com.sem4.security_springboot2.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.math.BigDecimal;

public record ProductRequest(
    @Schema(example = "Chuột không dây", description = "Tên sản phẩm")
    @NotBlank(message = "Tên sản phẩm không được để trống")
    @Size(max = 120, message = "Tên sản phẩm không quá 120 ký tự")
    String name,

    @Schema(example = "2.4GHz", description = "Mô tả sản phẩm")
    @Size(max = 500, message = "Mô tả không quá 500 ký tự")
    String description,

    @Schema(example = "350000", description = "Giá sản phẩm")
    @NotNull(message = "Giá sản phẩm không được để trống")
    @DecimalMin(value = "0.0", inclusive = false, message = "Giá sản phẩm phải lớn hơn 0")
    BigDecimal price
) {}
