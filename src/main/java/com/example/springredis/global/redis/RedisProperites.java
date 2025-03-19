package com.example.springredis.global.redis;

import lombok.Getter;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "spring.data.redis")
@Getter
public class RedisProperites {

    private final String host;
    private final int port;

    public RedisProperites(String host, int port) {
        this.host = host;
        this.port = port;
    }

}
