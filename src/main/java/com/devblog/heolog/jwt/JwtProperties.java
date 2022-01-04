package com.devblog.heolog.jwt;

public interface JwtProperties {
    String SECRET = "Heolog sign"; // 서버 비밀 값
    int EXPIRATION_TIME = 60000*10; // 10분
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
}
