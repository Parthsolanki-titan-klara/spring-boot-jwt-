package com.crackit.springsecurityjwt.user.reponse;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Date;
import java.util.List;

@RequiredArgsConstructor
public class ResponseUtil {

    public static ResponseEntity<Response> createResponse(String message, HttpStatus status) {
        GeneralResponse response = new GeneralResponse(message, new Date(), null);
        System.out.println("response : " + response);
        return new ResponseEntity<>(response, status);
    }


    public static ResponseEntity<Response> createListResponse(List<UserResponse> responses, String message, HttpStatus status) {
        GeneralResponse response = new GeneralResponse(message, new Date(), responses);
        System.out.println("response : " + response);
        return new ResponseEntity<>(response, status);
    }
}
