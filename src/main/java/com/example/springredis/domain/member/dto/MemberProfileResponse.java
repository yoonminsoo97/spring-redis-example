package com.example.springredis.domain.member.dto;

import com.example.springredis.domain.member.Member;

import lombok.Getter;

@Getter
public class MemberProfileResponse {

    private String nickname;
    private String username;

    public MemberProfileResponse(Member member) {
        this.nickname = member.getNickname();
        this.username = member.getUsername();
    }

}
