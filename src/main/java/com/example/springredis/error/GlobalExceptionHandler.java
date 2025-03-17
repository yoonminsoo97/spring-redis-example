package com.example.springredis.error;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(BaseException.class)
    public ResponseEntity<ErrorResponse> handle(BaseException ex) {
        ErrorResponse errorResponse = new ErrorResponse(ex.getErrorType());
        return ResponseEntity.status(errorResponse.getStatus()).body(errorResponse);
    }

}
