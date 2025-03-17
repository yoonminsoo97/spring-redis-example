package com.example.springredis.error;

import lombok.Getter;

@Getter
public class ErrorResponse {

    private int status;
    private String message;

    public ErrorResponse(ErrorType errorType) {
        this.status = errorType.getHttpStatus().value();
        this.message = errorType.getMessage();
    }

}
