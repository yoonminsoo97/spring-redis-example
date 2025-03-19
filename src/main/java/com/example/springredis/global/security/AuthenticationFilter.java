package com.example.springredis.global.security;

import com.example.springredis.domain.auth.TokenService;

import io.jsonwebtoken.Claims;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

@Component
@RequiredArgsConstructor
public class AuthenticationFilter extends OncePerRequestFilter {

    private final TokenService tokenService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String token = extractToken(request);
        tokenService.validateToken(token);
        Claims claims = tokenService.extractClaims(token);
        Authentication authentication = createAuthentication(claims);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(request, response);
    }

    private String extractToken(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");
        if (StringUtils.hasText(authorizationHeader) && authorizationHeader.startsWith("Bearer")) {
            return authorizationHeader.substring(7);
        }
        return null;
    }

    private Authentication createAuthentication(Claims claims) {
        String username = claims.get("username", String.class);
        String authority = claims.get("authority", String.class);
        return UsernamePasswordAuthenticationToken
                .authenticated(username, null, AuthorityUtils.createAuthorityList(authority));
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return RequestPath.isShouldNotFilter(request);
    }

    private enum RequestPath {

        LOGIN(HttpMethod.POST, "/api/auth/login", Authority.PERMIT_ALL),
        LOGOUT(HttpMethod.POST, "/api/auth/logout", Authority.ROLE_MEMBER),
        TOKEN_REISSUE(HttpMethod.POST, "/api/auth/token/reissue", Authority.PERMIT_ALL),
        MEMBER_PROFILE(HttpMethod.GET, "/api/members/me", Authority.ROLE_MEMBER);

        enum Authority {
            PERMIT_ALL, ROLE_MEMBER;
        }

        private final HttpMethod httpMethod;
        private final String pattern;
        private final Authority authority;

        RequestPath(HttpMethod httpMethod, String pattern, Authority authority) {
            this.httpMethod = httpMethod;
            this.pattern = pattern;
            this.authority = authority;
        }

        private static boolean isShouldNotFilter(HttpServletRequest request) {
            return Arrays.stream(RequestPath.values())
                    .anyMatch(
                            (requestPath) -> requestPath.authority.equals(Authority.PERMIT_ALL) &&
                                    antMatcher(requestPath.httpMethod, requestPath.pattern).matches(request)
                    );
        }

    }

}
