package com.sem4.security_springboot2.exception;

public class RefreshTokenReusedException extends RuntimeException {
    public RefreshTokenReusedException(String message) {
        super(message);
    }
}
