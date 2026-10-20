package com.sem4.security_springboot2.config;

import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@SecurityScheme(
    name = "bearerAuth",
    type = SecuritySchemeType.HTTP,
    scheme = "bearer",
    bearerFormat = "JWT",
    description = "Lấy token từ POST /api/auth/token rồi dán vào đây (không kèm chữ Bearer)"
)
public class OpenApiConfig {

    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("Catalog API với JWT và Spring Security 7")
                .description("Hệ thống quản lý phiên đăng nhập an toàn, refresh token rotation và OAuth2 Resource Server")
                .version("2.0.0"));
    }
}
