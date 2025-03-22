package com.example.springredis.domain.auth.jwt;

import lombok.RequiredArgsConstructor;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

@Component
@RequiredArgsConstructor
public class TokenStore {

    private static final String BLACKLIST_TOKEN_PREFIX = "black:";
    private static final String BLOCKED = "blocked";

    private final StringRedisTemplate stringRedisTemplate;

    public void addToken(String key, String value, long expire) {
        stringRedisTemplate.opsForValue().set(key, value, expire, TimeUnit.MILLISECONDS);
    }

    public void setTokenBlocked(String token, long expire) {
        stringRedisTemplate.opsForValue().set(BLACKLIST_TOKEN_PREFIX + token, BLOCKED, expire, TimeUnit.MILLISECONDS);
    }

    public void removeToken(String key) {
        if (!stringRedisTemplate.delete(key)) {
            throw new IllegalArgumentException("not found token!!");
        }
    }

    public boolean isTokenBlocked(String token) {
        return stringRedisTemplate.hasKey(BLACKLIST_TOKEN_PREFIX + token);
    }

    public String getToken(String key) {
        return stringRedisTemplate.opsForValue().get(key);
    }

}
