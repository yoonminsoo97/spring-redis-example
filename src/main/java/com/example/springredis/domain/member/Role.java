package com.example.springredis.domain.member;

import lombok.Getter;

@Getter
public enum Role {

    MEMBER("ROLE_MEMBER");

    private final String authority;

    Role(String authority) {
        this.authority = authority;
    }

}
