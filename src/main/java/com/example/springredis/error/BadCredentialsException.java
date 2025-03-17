package com.example.springredis.error;

public class BadCredentialsException extends BaseException {

    public BadCredentialsException() {
        super(ErrorType.BAD_CREDENTIALS);
    }

}
