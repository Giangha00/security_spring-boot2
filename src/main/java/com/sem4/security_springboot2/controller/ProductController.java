package com.sem4.security_springboot2.controller;

import com.sem4.security_springboot2.dto.ProductRequest;
import com.sem4.security_springboot2.dto.ProductResponse;
import com.sem4.security_springboot2.service.ProductService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/products")
@Tag(name = "Product", description = "Quản lý danh mục sản phẩm Catalog API")
public class ProductController {

    private final ProductService productService;

    public ProductController(ProductService productService) {
        this.productService = productService;
    }

    @Operation(summary = "Xem toàn bộ danh sách sản phẩm (công khai)")
    @ApiResponse(responseCode = "200", description = "Lấy danh sách sản phẩm thành công")
    @GetMapping
    public List<ProductResponse> getAll() {
        return productService.findAll();
    }

    @Operation(summary = "Xem chi tiết một sản phẩm theo ID (công khai)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Tìm thấy sản phẩm"),
        @ApiResponse(responseCode = "404", description = "Không tìm thấy sản phẩm",
            content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class)))
    })
    @GetMapping("/{id}")
    public ProductResponse getById(@PathVariable Long id) {
        return productService.findById(id);
    }

    @Operation(summary = "Tạo sản phẩm mới (Yêu cầu quyền SCOPE_product:write)")
    @SecurityRequirement(name = "bearerAuth")
    @ApiResponses({
        @ApiResponse(responseCode = "201", description = "Đã tạo sản phẩm thành công"),
        @ApiResponse(responseCode = "400", description = "Dữ liệu không hợp lệ",
            content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class))),
        @ApiResponse(responseCode = "401", description = "Thiếu token, token hết hạn hoặc sai chữ ký",
            content = @Content),
        @ApiResponse(responseCode = "403", description = "Token hợp lệ nhưng không có quyền SCOPE_product:write",
            content = @Content)
    })
    @PostMapping
    public ResponseEntity<ProductResponse> create(@Valid @RequestBody ProductRequest request) {
        ProductResponse response = productService.create(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @Operation(summary = "Cập nhật sản phẩm (Yêu cầu quyền SCOPE_product:write)")
    @SecurityRequirement(name = "bearerAuth")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Cập nhật sản phẩm thành công"),
        @ApiResponse(responseCode = "400", description = "Dữ liệu không hợp lệ",
            content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class))),
        @ApiResponse(responseCode = "401", description = "Thiếu token hoặc token không hợp lệ",
            content = @Content),
        @ApiResponse(responseCode = "403", description = "Token không có quyền SCOPE_product:write",
            content = @Content),
        @ApiResponse(responseCode = "404", description = "Không tìm thấy sản phẩm",
            content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class)))
    })
    @PutMapping("/{id}")
    public ProductResponse update(@PathVariable Long id, @Valid @RequestBody ProductRequest request) {
        return productService.update(id, request);
    }

    @Operation(summary = "Xóa sản phẩm (Yêu cầu quyền SCOPE_product:write)")
    @SecurityRequirement(name = "bearerAuth")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Xóa sản phẩm thành công"),
        @ApiResponse(responseCode = "401", description = "Thiếu token hoặc token không hợp lệ",
            content = @Content),
        @ApiResponse(responseCode = "403", description = "Token không có quyền SCOPE_product:write",
            content = @Content),
        @ApiResponse(responseCode = "404", description = "Không tìm thấy sản phẩm",
            content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class)))
    })
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        productService.delete(id);
        return ResponseEntity.noContent().build();
    }
}
