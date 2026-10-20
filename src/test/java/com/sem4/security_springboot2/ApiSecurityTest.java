package com.sem4.security_springboot2;

import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sem4.security_springboot2.dto.ProductRequest;
import com.sem4.security_springboot2.dto.ProductResponse;
import com.sem4.security_springboot2.service.ProductService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.io.File;
import java.io.InputStream;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class ApiSecurityTest {

    private static final String PRODUCT_JSON = """
        {"name":"Chuột không dây","description":"2.4GHz","price":350000}
        """;

    @Autowired
    private MockMvc mvc;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Autowired
    private ProductService productService;

    @Autowired
    private Map<String, RSAKey> rsaKeyMap;

    @Autowired
    private com.sem4.security_springboot2.config.RateLimitFilter rateLimitFilter;

    @Autowired
    private com.sem4.security_springboot2.repository.UserRepository userRepository;

    @org.junit.jupiter.api.BeforeEach
    void setUp() {
        rateLimitFilter.reset();
    }

    private String obtainToken(String username, String password) throws Exception {
        String body = mvc.perform(post("/api/auth/token")
                .contentType(APPLICATION_JSON)
                .content("""
                    {"username":"%s","password":"%s"}
                    """.formatted(username, password)))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        return JsonPath.read(body, "$.accessToken");
    }

    private String obtainRefreshToken(String username, String password) throws Exception {
        String body = mvc.perform(post("/api/auth/token")
                .contentType(APPLICATION_JSON)
                .content("""
                    {"username":"%s","password":"%s"}
                    """.formatted(username, password)))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        return JsonPath.read(body, "$.refreshToken");
    }

    // ==========================================
    // 10.3 Base Tutorial Tests
    // ==========================================

    @Test
    @DisplayName("Đăng nhập đúng trả token ký RSA có roles và scopes")
    void validCredentialsReturnSignedToken() throws Exception {
        String token = obtainToken("admin", "Admin#Test2026");
        Jwt jwt = jwtDecoder.decode(token);
        assertThat(jwt.getSubject()).isEqualTo("admin");
        assertThat(jwt.getClaimAsStringList("roles")).contains("ROLE_USER", "ROLE_ADMIN");
        assertThat(jwt.getClaimAsString("scope")).contains("product:read", "product:write");
    }

    @Test
    @DisplayName("Đăng nhập sai trả 401 kèm ProblemDetail")
    void wrongPasswordReturnsProblemDetail() throws Exception {
        mvc.perform(post("/api/auth/token")
                .contentType(APPLICATION_JSON)
                .content("""
                    {"username":"admin","password":"wrong"}
                    """))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.title").value("Authentication failed"));
    }

    @Test
    @DisplayName("Xem sản phẩm công khai không cần token")
    void anyoneCanReadProducts() throws Exception {
        mvc.perform(get("/api/v1/products"))
            .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Ghi sản phẩm không token trả 401 kèm WWW-Authenticate: Bearer")
    void writeWithoutTokenReturns401WithBearerChallenge() throws Exception {
        mvc.perform(post("/api/v1/products")
                .contentType(APPLICATION_JSON)
                .content(PRODUCT_JSON))
            .andExpect(status().isUnauthorized())
            .andExpect(header().string("WWW-Authenticate", startsWith("Bearer")));
    }

    @Test
    @DisplayName("Role USER không có quyền ghi sản phẩm (403 Forbidden)")
    void userRoleCannotCreateProduct() throws Exception {
        mvc.perform(post("/api/v1/products")
                .contentType(APPLICATION_JSON)
                .content(PRODUCT_JSON)
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_USER"))))
            .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Token có SCOPE_product:write tạo được sản phẩm mới (201 Created)")
    void adminScopeCanCreateProduct() throws Exception {
        mvc.perform(post("/api/v1/products")
                .contentType(APPLICATION_JSON)
                .content(PRODUCT_JSON)
                .with(jwt().authorities(new SimpleGrantedAuthority("SCOPE_product:write"))))
            .andExpect(status().isCreated());
    }

    @Test
    @DisplayName("Token không đúng định dạng bị từ chối 401")
    void malformedTokenIsRejected() throws Exception {
        mvc.perform(get("/api/auth/me")
                .header(AUTHORIZATION, "Bearer not-a-real-token"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Token thật hoạt động end-to-end tại /api/auth/me")
    void realTokenWorksEndToEnd() throws Exception {
        String token = obtainToken("admin", "Admin#Test2026");
        mvc.perform(get("/api/auth/me")
                .header(AUTHORIZATION, "Bearer " + token))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.username").value("admin"));
    }

    @Test
    @DisplayName("Bảo vệ lớp thứ 2: gọi trực tiếp Service không có quyền bị chặn bởi @PreAuthorize")
    @WithMockUser(roles = "USER")
    void serviceRejectsNonAdminEvenWithoutHttp() {
        assertThatThrownBy(() -> productService.create(
            new ProductRequest("Bàn phím", null, BigDecimal.TEN)))
            .isInstanceOf(AccessDeniedException.class);
    }

    // ==========================================
    // 11.4 Assignment Requirements Tests (R1 - R10)
    // ==========================================

    @Test
    @DisplayName("R1 & R2: Xoay vòng refresh token thành công, nhận cặp token mới")
    void refreshTokenRotationSuccess() throws Exception {
        String refreshToken1 = obtainRefreshToken("admin", "Admin#Test2026");
        assertThat(refreshToken1).isNotBlank();

        String body = mvc.perform(post("/api/auth/refresh")
                .contentType(APPLICATION_JSON)
                .content("""
                    {"refreshToken":"%s"}
                    """.formatted(refreshToken1)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.accessToken").isNotEmpty())
            .andExpect(jsonPath("$.refreshToken").isNotEmpty())
            .andReturn().getResponse().getContentAsString();

        String refreshToken2 = JsonPath.read(body, "$.refreshToken");
        assertThat(refreshToken2).isNotEqualTo(refreshToken1);
    }

    @Test
    @DisplayName("R3: Dùng lại refresh token cũ làm cả chuỗi family bị thu hồi, trả 401 REFRESH_TOKEN_REUSED")
    void reuseOldRefreshTokenRevokesFamily() throws Exception {
        String refreshToken1 = obtainRefreshToken("admin", "Admin#Test2026");

        // Lần 1: Xoay vòng hợp lệ -> cấp refreshToken2, đánh dấu refreshToken1 là đã dùng
        String body = mvc.perform(post("/api/auth/refresh")
                .contentType(APPLICATION_JSON)
                .content("""
                    {"refreshToken":"%s"}
                    """.formatted(refreshToken1)))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        String refreshToken2 = JsonPath.read(body, "$.refreshToken");

        // Lần 2: Gửi lại refreshToken1 (đã dùng) -> Phát hiện dùng lại!
        mvc.perform(post("/api/auth/refresh")
                .contentType(APPLICATION_JSON)
                .content("""
                    {"refreshToken":"%s"}
                    """.formatted(refreshToken1)))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.code").value("REFRESH_TOKEN_REUSED"));

        // Lần 3: Thử dùng refreshToken2 (cùng family) -> Đã bị thu hồi do family bị vô hiệu hóa
        mvc.perform(post("/api/auth/refresh")
                .contentType(APPLICATION_JSON)
                .content("""
                    {"refreshToken":"%s"}
                    """.formatted(refreshToken2)))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("R4: Access token bị từ chối sau khi logout và refresh token cũng bị thu hồi")
    void accessTokenRejectedAfterLogout() throws Exception {
        String body = mvc.perform(post("/api/auth/token")
                .contentType(APPLICATION_JSON)
                .content("""
                    {"username":"admin","password":"Admin#Test2026"}
                    """))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        String token = JsonPath.read(body, "$.accessToken");
        String refreshToken = JsonPath.read(body, "$.refreshToken");

        // Kiểm tra token hoạt động bình thường
        mvc.perform(get("/api/auth/me")
                .header(AUTHORIZATION, "Bearer " + token))
            .andExpect(status().isOk());

        // Đăng xuất và gửi kèm refreshToken cần thu hồi
        mvc.perform(post("/api/auth/logout")
                .header(AUTHORIZATION, "Bearer " + token)
                .contentType(APPLICATION_JSON)
                .content("""
                    {"refreshToken":"%s"}
                    """.formatted(refreshToken)))
            .andExpect(status().isNoContent());

        // 1. Gọi lại bằng access token vừa đăng xuất -> 401 Unauthorized (JTI revoked)
        mvc.perform(get("/api/auth/me")
                .header(AUTHORIZATION, "Bearer " + token))
            .andExpect(status().isUnauthorized());

        // 2. Thử xoay vòng bằng refresh token vừa đăng xuất -> 401 Unauthorized (Refresh token revoked)
        mvc.perform(post("/api/auth/refresh")
                .contentType(APPLICATION_JSON)
                .content("""
                    {"refreshToken":"%s"}
                    """.formatted(refreshToken)))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("R6: ADMIN khóa tài khoản làm vô hiệu hóa toàn bộ token của người dùng đó ngay lập tức")
    void adminLockUserRevokesAllTokensImmediately() throws Exception {
        String adminToken = obtainToken("admin", "Admin#Test2026");
        String userToken = obtainToken("user", "User#Catalog2026");

        // 1. User token ban đầu hoạt động bình thường
        mvc.perform(get("/api/auth/me")
                .header(AUTHORIZATION, "Bearer " + userToken))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.username").value("user"));

        // 2. User bình thường cố gọi API khóa tài khoản -> 403 Forbidden
        mvc.perform(post("/api/admin/users/user/lock")
                .header(AUTHORIZATION, "Bearer " + userToken))
            .andExpect(status().isForbidden());

        // 3. ADMIN gọi API khóa tài khoản 'user' -> 204 No Content
        mvc.perform(post("/api/admin/users/user/lock")
                .header(AUTHORIZATION, "Bearer " + adminToken))
            .andExpect(status().isNoContent());

        // 4. Token của 'user' lập tức bị JwtDecoder từ chối -> 401 Unauthorized
        mvc.perform(get("/api/auth/me")
                .header(AUTHORIZATION, "Bearer " + userToken))
            .andExpect(status().isUnauthorized());

        // 5. Thử đăng nhập lại bằng tài khoản vừa bị khóa -> 401 Unauthorized
        mvc.perform(post("/api/auth/token")
                .contentType(APPLICATION_JSON)
                .content("""
                    {"username":"user","password":"User#Catalog2026"}
                    """))
            .andExpect(status().isUnauthorized());

        // Khôi phục mở khóa cho 'user' để các test khác tiếp tục chạy bình thường
        com.sem4.security_springboot2.entity.User u = userRepository.findByUsername("user").orElseThrow();
        u.setEnabled(true);
        userRepository.save(u);
    }

    @Test
    @DisplayName("R5 & R6: Mọi access token bị từ chối sau logout-all và sau đổi mật khẩu")
    void allTokensRejectedAfterLogoutAllAndChangePassword() throws Exception {
        // Part 1: Kiểm tra logout-all
        String token1 = obtainToken("admin", "Admin#Test2026");
        mvc.perform(get("/api/auth/me")
                .header(AUTHORIZATION, "Bearer " + token1))
            .andExpect(status().isOk());

        mvc.perform(post("/api/auth/logout-all")
                .header(AUTHORIZATION, "Bearer " + token1))
            .andExpect(status().isNoContent());

        // token1 phải bị từ chối vì token_version của user đã tăng
        mvc.perform(get("/api/auth/me")
                .header(AUTHORIZATION, "Bearer " + token1))
            .andExpect(status().isUnauthorized());

        // Part 2: Đổi mật khẩu
        String token2 = obtainToken("admin", "Admin#Test2026");
        mvc.perform(get("/api/auth/me")
                .header(AUTHORIZATION, "Bearer " + token2))
            .andExpect(status().isOk());

        mvc.perform(post("/api/auth/change-password")
                .header(AUTHORIZATION, "Bearer " + token2)
                .contentType(APPLICATION_JSON)
                .content("""
                    {"currentPassword":"Admin#Test2026","newPassword":"NewAdmin#Test2026"}
                    """))
            .andExpect(status().isNoContent());

        // token2 phải bị từ chối
        mvc.perform(get("/api/auth/me")
                .header(AUTHORIZATION, "Bearer " + token2))
            .andExpect(status().isUnauthorized());

        // Khôi phục mật khẩu cũ để các test khác tiếp tục chạy
        String token3 = obtainToken("admin", "NewAdmin#Test2026");
        mvc.perform(post("/api/auth/change-password")
                .header(AUTHORIZATION, "Bearer " + token3)
                .contentType(APPLICATION_JSON)
                .content("""
                    {"currentPassword":"NewAdmin#Test2026","newPassword":"Admin#Test2026"}
                    """))
            .andExpect(status().isNoContent());
    }

    @Test
    @DisplayName("R7: Token ký bằng khóa cũ (test-key-2) vẫn được chấp nhận hợp lệ")
    void tokenSignedWithOldKeyIsAccepted() throws Exception {
        RSAKey oldKey = rsaKeyMap.get("test-key-2");
        assertThat(oldKey).isNotNull();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
            .keyID("test-key-2")
            .build();

        Date now = new Date();
        int currentVer = userRepository.findByUsername("admin")
            .map(com.sem4.security_springboot2.entity.User::getTokenVersion)
            .orElse(1);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .issuer("catalog-api")
            .subject("admin")
            .issueTime(now)
            .expirationTime(new Date(now.getTime() + 900_000))
            .jwtID(UUID.randomUUID().toString())
            .claim("roles", List.of("ROLE_USER", "ROLE_ADMIN"))
            .claim("scope", "product:read product:write")
            .claim("ver", currentVer)
            .build();

        SignedJWT signedJwt = new SignedJWT(header, claims);
        signedJwt.sign(new RSASSASigner(oldKey.toRSAPrivateKey()));
        String oldToken = signedJwt.serialize();

        mvc.perform(get("/api/auth/me")
                .header(AUTHORIZATION, "Bearer " + oldToken))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.username").value("admin"));
    }

    @Test
    @DisplayName("R7: Token có kid lạ không tồn tại trong JWK Set bị từ chối 401")
    void tokenWithUnknownKidIsRejected() throws Exception {
        RSAPrivateKey unknownPrivateKey;
        try (InputStream is = new ClassPathResource("keys/unknown.key").getInputStream()) {
            unknownPrivateKey = RsaKeyConverters.pkcs8().convert(is);
        }

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
            .keyID("unknown-key-xyz")
            .build();

        Date now = new Date();
        int currentVer = userRepository.findByUsername("admin")
            .map(com.sem4.security_springboot2.entity.User::getTokenVersion)
            .orElse(1);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .issuer("catalog-api")
            .subject("admin")
            .issueTime(now)
            .expirationTime(new Date(now.getTime() + 900_000))
            .jwtID(UUID.randomUUID().toString())
            .claim("roles", List.of("ROLE_USER"))
            .claim("ver", currentVer)
            .build();

        SignedJWT signedJwt = new SignedJWT(header, claims);
        signedJwt.sign(new RSASSASigner(unknownPrivateKey));
        String untrustedToken = signedJwt.serialize();

        mvc.perform(get("/api/auth/me")
                .header(AUTHORIZATION, "Bearer " + untrustedToken))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("R8: Endpoint /.well-known/jwks.json công bố đầy đủ khóa công khai và không lộ khóa bí mật")
    void jwksEndpointPublishesPublicKeysOnly() throws Exception {
        String response = mvc.perform(get("/.well-known/jwks.json"))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(jsonPath("$.keys").isArray())
            .andReturn().getResponse().getContentAsString();

        // Đảm bảo không chứa thuộc tính khóa bí mật của RSA như 'd', 'p', 'q', 'dp', 'dq', 'qi'
        assertThat(response).doesNotContain("\"d\":");
        assertThat(response).doesNotContain("\"p\":");
        assertThat(response).doesNotContain("\"q\":");
        assertThat(response).contains("test-key-1");
    }

    @Test
    @DisplayName("R10: Request thứ 11 trong 1 phút nhận HTTP 429 kèm Retry-After và ProblemDetail")
    void rateLimiterReturns429OnEleventhRequest() throws Exception {
        String testIp = "192.168.1.99";

        // Gửi 10 request đầu tiên từ IP này -> được xử lý
        for (int i = 0; i < 10; i++) {
            mvc.perform(post("/api/auth/token")
                .header("X-Forwarded-For", testIp)
                .contentType(APPLICATION_JSON)
                .content("""
                    {"username":"admin","password":"wrong-password"}
                    """))
                .andExpect(status().isUnauthorized());
        }

        // Request thứ 11 trong 1 phút -> 429 Too Many Requests
        mvc.perform(post("/api/auth/token")
                .header("X-Forwarded-For", testIp)
                .contentType(APPLICATION_JSON)
                .content("""
                    {"username":"admin","password":"Admin#Test2026"}
                    """))
            .andExpect(status().isTooManyRequests())
            .andExpect(header().exists("Retry-After"))
            .andExpect(jsonPath("$.title").value("Too Many Requests"))
            .andExpect(jsonPath("$.status").value(429));
    }

    @Test
    @DisplayName("Xuất tài liệu docs/api/openapi.yaml từ springdoc (11.4)")
    void exportOpenApiYaml() throws Exception {
        String yamlContent = mvc.perform(get("/v3/api-docs.yaml"))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString(java.nio.charset.StandardCharsets.UTF_8);

        File docsDir = new File("docs/api");
        if (!docsDir.exists()) {
            docsDir.mkdirs();
        }
        Files.writeString(Path.of("docs/api/openapi.yaml"), yamlContent, java.nio.charset.StandardCharsets.UTF_8);
        assertThat(new File("docs/api/openapi.yaml")).exists();
    }
}
