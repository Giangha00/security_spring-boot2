package com.sem4.security_springboot2.controller;

import com.nimbusds.jose.jwk.JWKSet;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@Tag(name = "JWKS", description = "Công bố danh sách khóa công khai đang hiệu lực")
public class JwksController {

    private final JWKSet jwkSet;

    public JwksController(JWKSet jwkSet) {
        this.jwkSet = jwkSet;
    }

    @Operation(summary = "Công bố các khóa công khai theo chuẩn JWK Set (R8)")
    @ApiResponse(responseCode = "200", description = "Danh sách khóa công khai đang hiệu lực")
    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> jwks() {
        // toPublicJWKSet() đảm bảo tuyệt đối không lộ bất kỳ thông tin nào của khóa bí mật
        return jwkSet.toPublicJWKSet().toJSONObject();
    }
}
