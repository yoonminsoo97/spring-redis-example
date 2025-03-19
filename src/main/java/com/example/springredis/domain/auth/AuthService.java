package com.example.springredis.domain.auth;

import com.example.springredis.domain.auth.dto.LoginRequest;
import com.example.springredis.domain.auth.dto.TokenResponse;
import com.example.springredis.domain.member.Member;
import com.example.springredis.domain.member.MemberRepository;

import lombok.RequiredArgsConstructor;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    @Transactional
    public TokenResponse login(LoginRequest loginRequest) {
        Member member = memberRepository.findByUsername(loginRequest.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("bad credentials!!"));
        if (!passwordEncoder.matches(loginRequest.getPassword(), member.getPassword())) {
            throw new IllegalArgumentException("bad credentials!!");
        }
        return tokenService.issueToken(member.getUsername(), member.getAuthority());
    }

    @Transactional
    public void logout(String username, String accessToken) {
        tokenService.deleteToken(username, accessToken);
    }

    @Transactional
    public TokenResponse reIssueToken(String refreshToken) {
        String username = tokenService.extractClaims(refreshToken).get("username", String.class);
        Member member = memberRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("not found member"));
        return tokenService.reIssueToken(member.getUsername(), member.getAuthority(), refreshToken);
    }

}
