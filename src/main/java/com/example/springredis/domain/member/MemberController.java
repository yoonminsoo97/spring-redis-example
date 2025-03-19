package com.example.springredis.domain.member;

import com.example.springredis.domain.member.dto.MemberProfileResponse;

import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/members")
@RequiredArgsConstructor
public class MemberController {

    private final MemberService memberService;

    @PreAuthorize("hasRole('MEMBER')")
    @GetMapping("/me")
    public ResponseEntity<MemberProfileResponse> memberProfile(@AuthenticationPrincipal String username) {
        MemberProfileResponse memberProfileResponse = memberService.memberProfile(username);
        return ResponseEntity.ok().body(memberProfileResponse);
    }

}
