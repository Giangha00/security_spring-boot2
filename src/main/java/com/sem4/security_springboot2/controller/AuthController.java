package com.sem4.security_springboot2.controller;

import com.sem4.security_springboot2.dto.*;
import com.sem4.security_springboot2.entity.User;
import com.sem4.security_springboot2.service.RefreshTokenService;
import com.sem4.security_springboot2.service.RevocationService;
import com.sem4.security_springboot2.service.TokenService;
import com.sem4.security_springboot2.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@Tag(name = "Auth", description = "Cấp, làm mới, thu hồi token và quản lý phiên đăng nhập an toàn")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;
    private final RefreshTokenService refreshTokenService;
    private final RevocationService revocationService;
    private final UserService userService;

    public AuthController(AuthenticationManager authenticationManager,
                          TokenService tokenService,
                          RefreshTokenService refreshTokenService,
                          RevocationService revocationService,
                          UserService userService) {
        this.authenticationManager = authenticationManager;
        this.tokenService = tokenService;
        this.refreshTokenService = refreshTokenService;
        this.revocationService = revocationService;
        this.userService = userService;
    }

    @Operation(summary = "Đổi username/mật khẩu lấy access token và refresh token (R1)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Cấp token thành công"),
        @ApiResponse(responseCode = "400", description = "Dữ liệu yêu cầu không hợp lệ",
            content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class))),
        @ApiResponse(responseCode = "401", description = "Sai username hoặc mật khẩu",
            content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class))),
        @ApiResponse(responseCode = "429", description = "Quá giới hạn tần suất 10 request/phút",
            content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class)))
    })
    @PostMapping("/token")
    public TokenResponse token(@Valid @RequestBody LoginRequest request, HttpServletRequest httpRequest) {
        Authentication authentication = authenticationManager.authenticate(
            UsernamePasswordAuthenticationToken.unauthenticated(request.username(), request.password())
        );

        User user = userService.getByUsername(authentication.getName());
        String accessToken = tokenService.issueAccessToken(user);
        String ip = extractClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");
        String refreshToken = refreshTokenService.createRefreshToken(user, ip, userAgent);

        return new TokenResponse(accessToken, "Bearer", tokenService.getTtl().toSeconds(), refreshToken);
    }

    @Operation(summary = "Xoay vòng refresh token để lấy cặp token mới (R2, R3)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Làm mới token thành công"),
        @ApiResponse(responseCode = "400", description = "Dữ liệu yêu cầu không hợp lệ",
            content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class))),
        @ApiResponse(responseCode = "401", description = "Refresh token không hợp lệ, đã hết hạn hoặc bị dùng lại (REFRESH_TOKEN_REUSED)",
            content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class))),
        @ApiResponse(responseCode = "429", description = "Quá giới hạn tần suất 10 request/phút",
            content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class)))
    })
    @PostMapping("/refresh")
    public TokenResponse refresh(@Valid @RequestBody RefreshTokenRequest request, HttpServletRequest httpRequest) {
        String ip = extractClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");
        return refreshTokenService.rotateRefreshToken(request.refreshToken(), ip, userAgent);
    }

    @Operation(summary = "Xem thông tin token đang dùng")
    @SecurityRequirement(name = "bearerAuth")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Lấy thông tin thành công"),
        @ApiResponse(responseCode = "401", description = "Token không hợp lệ, hết hạn hoặc đã bị thu hồi",
            content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class)))
    })
    @GetMapping("/me")
    public MeResponse me(@AuthenticationPrincipal Jwt jwt) {
        return new MeResponse(
            jwt.getSubject(),
            jwt.getClaimAsStringList("roles"),
            jwt.getExpiresAt()
        );
    }

    @Operation(summary = "Đăng xuất thiết bị hiện tại (R4)")
    @SecurityRequirement(name = "bearerAuth")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Đăng xuất thành công, access token đã bị đưa vào danh sách thu hồi"),
        @ApiResponse(responseCode = "401", description = "Chưa xác thực hoặc token không hợp lệ",
            content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class)))
    })
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@AuthenticationPrincipal Jwt jwt,
                                       @RequestBody(required = false) LogoutRequest request) {
        // Đưa JTI của access token hiện tại vào danh sách thu hồi cho đến khi hết hạn
        revocationService.revokeAccessToken(jwt.getId(), jwt.getExpiresAt());

        if (request != null && request.refreshToken() != null) {
            refreshTokenService.revokeToken(request.refreshToken());
        }

        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "Đăng xuất mọi thiết bị (R5)")
    @SecurityRequirement(name = "bearerAuth")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Đã thu hồi tất cả refresh token và làm mất hiệu lực toàn bộ access token"),
        @ApiResponse(responseCode = "401", description = "Chưa xác thực hoặc token không hợp lệ",
            content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class)))
    })
    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAll(@AuthenticationPrincipal Jwt jwt) {
        String username = jwt.getSubject();
        User user = userService.getByUsername(username);

        // Thu hồi toàn bộ refresh token của người dùng
        refreshTokenService.revokeAllForUser(user.getId());

        // Tăng token_version làm mất hiệu lực mọi access token đã phát hành
        userService.incrementTokenVersion(username);
        revocationService.invalidateUserCache(username);

        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "Đổi mật khẩu người dùng (R6)")
    @SecurityRequirement(name = "bearerAuth")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Đổi mật khẩu thành công, toàn bộ token cũ đã mất hiệu lực"),
        @ApiResponse(responseCode = "400", description = "Mật khẩu mới không hợp lệ",
            content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class))),
        @ApiResponse(responseCode = "401", description = "Mật khẩu hiện tại không đúng hoặc chưa xác thực",
            content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class)))
    })
    @PostMapping("/change-password")
    public ResponseEntity<Void> changePassword(@AuthenticationPrincipal Jwt jwt,
                                               @Valid @RequestBody ChangePasswordRequest request) {
        String username = jwt.getSubject();
        User user = userService.getByUsername(username);

        userService.changePassword(username, request.currentPassword(), request.newPassword());
        refreshTokenService.revokeAllForUser(user.getId());
        revocationService.invalidateUserCache(username);

        return ResponseEntity.noContent().build();
    }

    private String extractClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
