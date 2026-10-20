package com.sem4.security_springboot2.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(prefix = "app.jwt")
@Getter
@Setter
public class JwtProperties {
    private String issuer = "catalog-api";
    private Duration ttl = Duration.ofMinutes(15);
    private String activeKid = "key-1";
    private List<KeyEntry> keys = new ArrayList<>();

    @Getter
    @Setter
    public static class KeyEntry {
        private String kid;
        private Resource publicKey;
        private Resource privateKey;
    }
}
