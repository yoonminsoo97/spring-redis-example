package com.example.springredis.error;

import lombok.Getter;

import org.springframework.http.HttpStatus;

import java.util.Arrays;

@Getter
public enum ErrorType {

    UNSUPPORT_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "E00000", "지원하지 않는 예외 유형입니다."),
    BAD_CREDENTIALS(HttpStatus.UNAUTHORIZED, "E401001", "아이디 또는 비밀번호가 일치하지 않습니다."),
    EXPIRED_TOKEN(HttpStatus.UNAUTHORIZED, "E401002", "토큰이 만료되었습니다."),
    INVALID_TOKEN(HttpStatus.UNAUTHORIZED, "E401003", "토큰이 유효하지 않습니다.");

    private final HttpStatus httpStatus;
    private final String errorCode;
    private final String message;

    ErrorType(HttpStatus httpStatus, String errorCode, String message) {
        this.httpStatus = httpStatus;
        this.errorCode = errorCode;
        this.message = message;
    }

    public static ErrorType of(String errorCode) {
        return Arrays.stream(ErrorType.values())
                .filter((errorType) -> errorType.errorCode.equals(errorCode))
                .findFirst()
                .orElse(ErrorType.UNSUPPORT_ERROR);
    }

}
