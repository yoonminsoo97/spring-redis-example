package com.example.springredis.domain.auth;

import com.example.springredis.domain.auth.dto.TokenResponse;
import com.example.springredis.domain.auth.jwt.TokenManager;

import io.jsonwebtoken.Claims;

import lombok.RequiredArgsConstructor;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class TokenService {

    private static final String BLACKLIST_KEY_PREFIX = "black:";
    private static final String BLACKLIST_VALUE = "blocked";

    private final TokenManager tokenManager;
    private final StringRedisTemplate stringRedisTemplate;

    public TokenResponse issueToken(String username, String authority) {
        String accessToken = tokenManager.createAccessToken(username, authority);
        String refreshToken = tokenManager.createRefreshToken(username);
        saveToken(username, refreshToken, tokenManager.getRefreshTokenExpire());
        return new TokenResponse(accessToken, refreshToken);
    }

    public TokenResponse reIssueToken(String username, String authority, String oldRefreshToken) {
        validateToken(oldRefreshToken);
        String newAccessToken = tokenManager.createAccessToken(username, authority);
        String newRefreshToken = tokenManager.createRefreshToken(username);
        setTokenBlackList(oldRefreshToken, tokenManager.getRefreshTokenExpire());
        saveToken(username, newRefreshToken, tokenManager.getRefreshTokenExpire());
        return new TokenResponse(newAccessToken, newRefreshToken);
    }

    public void deleteToken(String username, String accessToken) {
        setTokenBlackList(accessToken, tokenManager.getAccessTokenExpire());
        setTokenBlackList(stringRedisTemplate.opsForValue().get(username), tokenManager.getRefreshTokenExpire());
        Boolean isDelete = stringRedisTemplate.delete(username);
        if (!isDelete) {
            throw new IllegalArgumentException("not found refresh token!!");
        }
    }

    public void validateToken(String token) {
        if (isBlack(token)) {
            throw new AuthenticationServiceException("this token is blocked!!");
        }
        tokenManager.validateToken(token);
    }

    public Claims extractClaims(String token) {
        return tokenManager.extractClaims(token);
    }

    private void saveToken(String key, String value, long expire) {
        stringRedisTemplate.opsForValue().set(key, value, expire, TimeUnit.MILLISECONDS);
    }

    private void setTokenBlackList(String token, long expire) {
        saveToken(BLACKLIST_KEY_PREFIX + token, BLACKLIST_VALUE, expire);
    }

    private boolean isBlack(String token) {
        return stringRedisTemplate.hasKey(BLACKLIST_KEY_PREFIX + token);
    }

}
