package com.sem4.security_springboot2.service;

import com.sem4.security_springboot2.config.JwtProperties;
import com.sem4.security_springboot2.dto.TokenResponse;
import com.sem4.security_springboot2.entity.User;
import com.sem4.security_springboot2.repository.UserRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
public class TokenService {
    private final JwtEncoder encoder;
    private final JwtProperties properties;
    private final UserRepository userRepository;

    public TokenService(JwtEncoder encoder,
                        JwtProperties properties,
                        UserRepository userRepository) {
        this.encoder = encoder;
        this.properties = properties;
        this.userRepository = userRepository;
    }

    public Duration getTtl() {
        return properties.getTtl();
    }

    public String getIssuer() {
        return properties.getIssuer();
    }

    public String issueAccessToken(User user) {
        Instant now = Instant.now();

        List<String> roles = user.getRoles().stream()
            .map(r -> r.getName())
            .filter(name -> name.startsWith("ROLE_"))
            .toList();

        // R9: Derive scopes from roles
        Set<String> scopes = new LinkedHashSet<>();
        if (roles.contains("ROLE_USER")) {
            scopes.add("product:read");
        }
        if (roles.contains("ROLE_ADMIN")) {
            scopes.add("product:read");
            scopes.add("product:write");
        }
        String scopeClaim = String.join(" ", scopes);

        JwtClaimsSet claims = JwtClaimsSet.builder()
            .issuer(properties.getIssuer())
            .issuedAt(now)
            .expiresAt(now.plus(properties.getTtl()))
            .subject(user.getUsername())
            .id(UUID.randomUUID().toString())
            .claim("roles", roles)
            .claim("scope", scopeClaim)
            .claim("ver", user.getTokenVersion())
            .build();

        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256)
            .keyId(properties.getActiveKid())
            .build();

        return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }

    public String issueAccessToken(Authentication authentication) {
        String username = authentication.getName();
        User user = userRepository.findByUsername(UserService.normalize(username))
            .orElseGet(() -> {
                User u = new User();
                u.setUsername(username);
                u.setTokenVersion(1);
                return u;
            });
        return issueAccessToken(user);
    }
}
