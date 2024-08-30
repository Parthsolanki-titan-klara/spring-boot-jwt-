package com.crackit.springsecurityjwt.exception;

import lombok.*;

import java.util.Date;

@Data
@Builder
@RequiredArgsConstructor
@AllArgsConstructor
public class CustomException extends RuntimeException{
    private String message;
    private Date timeStamp;
}
