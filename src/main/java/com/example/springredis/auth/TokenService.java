package com.example.springredis.auth;

import com.example.springredis.auth.jwt.JwtManager;
import com.example.springredis.error.ErrorType;
import com.example.springredis.member.Member;

import io.jsonwebtoken.Claims;

import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final JwtManager jwtManager;
    private final StringRedisTemplate stringRedisTemplate;

    private static final String BLACKLIST_PREFIX = "blacklist:";

    @Value("${jwt.access-token.expire}")
    private long accessTokenExpire;

    @Value("${jwt.refresh-token.expire}")
    private long refreshTokenExpire;

    public TokenResponse saveToken(Member member) {
        String accessToken = jwtManager.createAccessToken(member.getUsername(), member.getAuthority());
        String refreshToken = jwtManager.createRefreshToken();
        stringRedisTemplate.opsForValue().set(member.getUsername(), refreshToken, refreshTokenExpire, TimeUnit.MILLISECONDS);
        return new TokenResponse(accessToken, refreshToken);
    }

    public void deleteToken(String username, String accessToken) {
        String refreshToken = stringRedisTemplate.opsForValue().get(username);
        setBlackList(accessToken, refreshToken);
        stringRedisTemplate.delete(username);
    }

    private void setBlackList(String accessToken, String refreshToken) {
        stringRedisTemplate.opsForValue().set(BLACKLIST_PREFIX + accessToken, "BLACK", accessTokenExpire, TimeUnit.MILLISECONDS);
        stringRedisTemplate.opsForValue().set(BLACKLIST_PREFIX + refreshToken, "BLACK", refreshTokenExpire, TimeUnit.MILLISECONDS);
    }

    public Claims getClaims(String token) {
        return jwtManager.getClaims(token);
    }

    public void validateToken(String token) {
        jwtManager.validateToken(token);
        if (isBlackList(token)) {
            throw new AuthenticationServiceException(ErrorType.INVALID_TOKEN.getMessage());
        }
    }

    private boolean isBlackList(String token) {
        return stringRedisTemplate.hasKey(BLACKLIST_PREFIX + token);
    }

}
