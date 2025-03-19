package com.example.springredis.domain.member;

import com.example.springredis.domain.member.dto.MemberProfileResponse;

import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;

    @Transactional
    public MemberProfileResponse memberProfile(String username) {
        Member member = memberRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("not found member"));
        return new MemberProfileResponse(member);
    }

}
