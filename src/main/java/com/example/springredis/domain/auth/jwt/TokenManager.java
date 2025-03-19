package com.example.springredis.domain.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;

import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class TokenManager {

    private final SecretKey secretKey;
    private final long accessTokenExpire;
    private final long refreshTokenExpire;

    public TokenManager(TokenProperties tokenProperties) {
        this.secretKey = Keys.hmacShaKeyFor(tokenProperties.getSecretKey().getBytes(StandardCharsets.UTF_8));
        this.accessTokenExpire = tokenProperties.getAccessTokenExpire();
        this.refreshTokenExpire = tokenProperties.getRefreshTokenExpire();
    }

    public String createAccessToken(String username, String authority) {
        Date iat = new Date();
        Date exp = new Date(iat.getTime() + accessTokenExpire);
        return Jwts.builder()
                .claim("username", username)
                .claim("authority", authority)
                .issuedAt(iat)
                .expiration(exp)
                .signWith(secretKey, Jwts.SIG.HS256)
                .compact();
    }

    public String createRefreshToken(String username) {
        Date iat = new Date();
        Date exp = new Date(iat.getTime() + refreshTokenExpire);
        return Jwts.builder()
                .claim("username", username)
                .issuedAt(iat)
                .expiration(exp)
                .signWith(secretKey, Jwts.SIG.HS256)
                .compact();
    }

    public Claims extractClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public void validateToken(String token) {
        try {
            Jwts.parser().verifyWith(secretKey).build().parse(token);
        } catch (ExpiredJwtException ex) {
            throw new AuthenticationServiceException("expired token");
        } catch (JwtException | IllegalArgumentException ex) {
            throw new AuthenticationServiceException("invalid token");
        }
    }

    public long getAccessTokenExpire() {
        return accessTokenExpire;
    }

    public long getRefreshTokenExpire() {
        return refreshTokenExpire;
    }

}
