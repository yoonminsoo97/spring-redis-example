package com.example.springredis.global.redis;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;

@Configuration
public class RedisConfig {

    @Bean
    public RedisConnectionFactory redisConnectionFactory(RedisProperites redisProperites) {
        return new LettuceConnectionFactory(redisProperites.getHost(), redisProperites.getPort());
    }

}
