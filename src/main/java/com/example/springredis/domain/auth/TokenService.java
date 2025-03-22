package com.example.springredis.domain.auth;

import com.example.springredis.domain.auth.dto.TokenResponse;
import com.example.springredis.domain.auth.jwt.TokenManager;
import com.example.springredis.domain.auth.jwt.TokenStore;

import io.jsonwebtoken.Claims;

import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final TokenManager tokenManager;
    private final TokenStore tokenStore;

    public TokenResponse issueToken(String username, String authority) {
        String accessToken = tokenManager.createAccessToken(username, authority);
        String refreshToken = tokenManager.createRefreshToken(username);
        tokenStore.addToken(username, refreshToken, tokenManager.getRefreshTokenExpire());
        return new TokenResponse(accessToken, refreshToken);
    }

    public TokenResponse reIssueToken(String username, String authority, String oldRefreshToken) {
        validateToken(oldRefreshToken);
        String newAccessToken = tokenManager.createAccessToken(username, authority);
        String newRefreshToken = tokenManager.createRefreshToken(username);
        tokenStore.setTokenBlocked(oldRefreshToken, tokenManager.getRefreshTokenExpire());
        tokenStore.addToken(username, newRefreshToken, tokenManager.getRefreshTokenExpire());
        return new TokenResponse(newAccessToken, newRefreshToken);
    }

    public void deleteToken(String username, String accessToken) {
        String refreshToken = tokenStore.getToken(username);
        tokenStore.setTokenBlocked(accessToken, tokenManager.getAccessTokenExpire());
        tokenStore.setTokenBlocked(refreshToken, tokenManager.getRefreshTokenExpire());
        tokenStore.removeToken(username);
    }

    public void validateToken(String token) {
        if (tokenStore.isTokenBlocked(token)) {
            throw new IllegalArgumentException("this token is blocked!!");
        }
        tokenManager.validateToken(token);
    }

    public Claims extractClaims(String token) {
        return tokenManager.extractClaims(token);
    }

}
