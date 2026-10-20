package com.sem4.security_springboot2.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Component
public class RateLimitFilter extends OncePerRequestFilter {
    private final ConcurrentMap<String, Deque<Instant>> ipRequestLogs = new ConcurrentHashMap<>();
    private final int limitPerMinute;
    private final ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();

    public RateLimitFilter(@Value("${app.rate-limit.limit-per-minute:10}") int limitPerMinute) {
        this.limitPerMinute = limitPerMinute;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String uri = request.getRequestURI();

        if (uri.equals("/api/auth/token") || uri.equals("/api/auth/refresh")) {
            String clientIp = getClientIp(request);
            Instant now = Instant.now();
            Instant windowStart = now.minus(Duration.ofMinutes(1));

            Deque<Instant> timestamps = ipRequestLogs.computeIfAbsent(clientIp, k -> new ArrayDeque<>());

            synchronized (timestamps) {
                // Xóa các request cũ ngoài cửa sổ 1 phút
                while (!timestamps.isEmpty() && timestamps.peekFirst().isBefore(windowStart)) {
                    timestamps.pollFirst();
                }

                if (timestamps.size() >= limitPerMinute) {
                    Instant oldest = timestamps.peekFirst();
                    long retryAfterSeconds = Math.max(1, 60 - Duration.between(oldest, now).toSeconds());

                    response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                    response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
                    response.setCharacterEncoding("UTF-8");
                    response.setHeader("Retry-After", String.valueOf(retryAfterSeconds));

                    ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(
                        HttpStatus.TOO_MANY_REQUESTS,
                        "Quá giới hạn tần suất yêu cầu: tối đa " + limitPerMinute + " request mỗi phút"
                    );
                    problemDetail.setTitle("Too Many Requests");
                    problemDetail.setType(URI.create("https://api.catalog.local/errors/rate-limit-exceeded"));
                    problemDetail.setInstance(URI.create(uri));
                    problemDetail.setProperty("timestamp", now);

                    response.getWriter().write(objectMapper.writeValueAsString(problemDetail));
                    return;
                }

                timestamps.addLast(now);
            }
        }

        filterChain.doFilter(request, response);
    }

    public void reset() {
        ipRequestLogs.clear();
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
