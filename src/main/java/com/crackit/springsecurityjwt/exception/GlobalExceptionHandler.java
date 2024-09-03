package com.crackit.springsecurityjwt.exception;


import com.crackit.springsecurityjwt.user.reponse.Response;
import com.crackit.springsecurityjwt.user.reponse.ResponseUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(CustomException.class)
    public ResponseEntity<Response> handleCustomJwtException(CustomException ex) {
        log.error("JWT token error: {}", ex.getMessage(), ex);
        if (ex.getMessage().contains("expired")) {
            return ResponseUtil.createResponse("JWT token is expired", HttpStatus.UNAUTHORIZED);
        }
        return ResponseUtil.createResponse("JWT token error: " + ex.getMessage(), HttpStatus.BAD_REQUEST);
    }
}