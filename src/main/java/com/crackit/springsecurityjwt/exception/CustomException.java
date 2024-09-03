package com.crackit.springsecurityjwt.exception;

import lombok.*;
import org.springframework.http.HttpStatus;

import java.util.Date;

@Data
@Builder
@RequiredArgsConstructor
@AllArgsConstructor
public class CustomException extends RuntimeException{
    private String message;
    private Date timeStamp;
    private HttpStatus status;

    public CustomException(String jwtTokenIsExpired, HttpStatus httpStatus) {
        this.message = jwtTokenIsExpired;
        this.timeStamp = new Date();
        this.status = httpStatus;
    }
}
