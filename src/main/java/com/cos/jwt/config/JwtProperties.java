package com.cos.jwt.config;

public interface JwtProperties {

	String SECRET = "squish"; // 비밀값
	int EXPIRATION_TIME = 60000 * 100; // 100분
	String TOKEN_PREFIX = "Bearer ";
	String HEADER_STRING = "Authorization";
}
