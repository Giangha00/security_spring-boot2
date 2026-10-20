package com.sem4.security_springboot2.controller;

import com.sem4.security_springboot2.entity.User;
import com.sem4.security_springboot2.service.RefreshTokenService;
import com.sem4.security_springboot2.service.RevocationService;
import com.sem4.security_springboot2.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/users")
@Tag(name = "Admin", description = "Quản trị người dùng & khóa tài khoản (R6)")
public class AdminUserController {

    private final UserService userService;
    private final RefreshTokenService refreshTokenService;
    private final RevocationService revocationService;

    public AdminUserController(UserService userService,
                               RefreshTokenService refreshTokenService,
                               RevocationService revocationService) {
        this.userService = userService;
        this.refreshTokenService = refreshTokenService;
        this.revocationService = revocationService;
    }

    @Operation(summary = "ADMIN khóa tài khoản người dùng và vô hiệu hóa toàn bộ token (R6)")
    @SecurityRequirement(name = "bearerAuth")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Khóa tài khoản thành công, toàn bộ token đã bị vô hiệu hóa"),
        @ApiResponse(responseCode = "401", description = "Chưa xác thực hoặc token không hợp lệ"),
        @ApiResponse(responseCode = "403", description = "Không có quyền ADMIN"),
        @ApiResponse(responseCode = "404", description = "Không tìm thấy người dùng")
    })
    @PostMapping("/{username}/lock")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> lockUser(@PathVariable String username) {
        User user = userService.getByUsername(username);
        userService.lockUser(username);
        refreshTokenService.revokeAllForUser(user.getId());
        revocationService.invalidateUserCache(username);
        return ResponseEntity.noContent().build();
    }
}
