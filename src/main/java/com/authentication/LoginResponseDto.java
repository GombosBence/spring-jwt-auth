package com.authentication;

import org.springframework.http.ResponseCookie;

public record LoginResponseDto(ResponseCookie jwt, ResponseCookie refreshToken) {}
