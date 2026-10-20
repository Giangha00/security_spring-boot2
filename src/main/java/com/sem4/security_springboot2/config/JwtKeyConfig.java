package com.sem4.security_springboot2.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.converter.RsaKeyConverters;

import java.io.InputStream;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

@Configuration
@EnableConfigurationProperties(JwtProperties.class)
public class JwtKeyConfig {
    private final JwtProperties properties;

    public JwtKeyConfig(JwtProperties properties) {
        this.properties = properties;
    }

    @Bean
    public Map<String, RSAKey> rsaKeyMap() {
        Map<String, RSAKey> map = new LinkedHashMap<>();

        for (JwtProperties.KeyEntry entry : properties.getKeys()) {
            try {
                if (entry.getPublicKey() == null) {
                    continue;
                }

                RSAPublicKey publicKey;
                try (InputStream is = entry.getPublicKey().getInputStream()) {
                    publicKey = RsaKeyConverters.x509().convert(is);
                }

                RSAKey.Builder builder = new RSAKey.Builder(publicKey).keyID(entry.getKid());

                if (entry.getPrivateKey() != null) {
                    try (InputStream is = entry.getPrivateKey().getInputStream()) {
                        RSAPrivateKey privateKey = RsaKeyConverters.pkcs8().convert(is);
                        builder.privateKey(privateKey);
                    }
                }

                map.put(entry.getKid(), builder.build());
            } catch (Exception e) {
                throw new IllegalStateException("Failed to load RSA key for kid: " + entry.getKid(), e);
            }
        }

        if (map.isEmpty()) {
            throw new IllegalStateException("No valid RSA keys configured under app.jwt.keys");
        }

        return Collections.unmodifiableMap(map);
    }

    @Bean
    public JWKSet jwkSet(Map<String, RSAKey> rsaKeyMap) {
        return new JWKSet(new ArrayList<>(rsaKeyMap.values()));
    }
}
