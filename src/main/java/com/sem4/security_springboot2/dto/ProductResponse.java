package com.sem4.security_springboot2.dto;

import io.swagger.v3.oas.annotations.media.Schema;

import java.math.BigDecimal;
import java.time.Instant;

public record ProductResponse(
    @Schema(example = "1", description = "Mã sản phẩm")
    Long id,

    @Schema(example = "Chuột không dây", description = "Tên sản phẩm")
    String name,

    @Schema(example = "2.4GHz", description = "Mô tả sản phẩm")
    String description,

    @Schema(example = "350000.00", description = "Giá sản phẩm")
    BigDecimal price,

    @Schema(description = "Thời điểm tạo")
    Instant createdAt,

    @Schema(description = "Thời điểm cập nhật")
    Instant updatedAt
) {}
