package com.authentication;

import org.springframework.http.ResponseCookie;

public record CookieResponseDto(ResponseCookie jwt, ResponseCookie refreshToken) {}
