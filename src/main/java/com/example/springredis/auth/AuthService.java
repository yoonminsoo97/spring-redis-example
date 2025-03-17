package com.example.springredis.auth;

import com.example.springredis.error.BadCredentialsException;
import com.example.springredis.member.Member;
import com.example.springredis.member.MemberRepository;

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
                .orElseThrow(BadCredentialsException::new);
        if (!passwordEncoder.matches(loginRequest.getPassword(), member.getPassword())) {
            throw new BadCredentialsException();
        }
        return tokenService.saveToken(member);
    }

    @Transactional
    public void logout(String username, String accessToken) {
        tokenService.deleteToken(username, accessToken);
    }

}
