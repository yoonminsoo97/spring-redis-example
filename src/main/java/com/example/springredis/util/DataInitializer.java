package com.example.springredis.util;

import com.example.springredis.member.Member;
import com.example.springredis.member.MemberRepository;

import lombok.RequiredArgsConstructor;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class DataInitializer implements ApplicationRunner {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(ApplicationArguments args) {
        Member member = Member.builder()
                .nickname("yoonkun")
                .username("yoon1234")
                .password(passwordEncoder.encode("12345678"))
                .build();
        memberRepository.save(member);
    }

}
