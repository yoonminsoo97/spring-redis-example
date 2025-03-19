package com.example.springredis.domain.auth.dto;

import lombok.Getter;

@Getter
public class TokenResponse {

    private String accessToken;
    private String refreshToken;

    public TokenResponse(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

}
