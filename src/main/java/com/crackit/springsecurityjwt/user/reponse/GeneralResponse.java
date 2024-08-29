package com.crackit.springsecurityjwt.user.reponse;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;

import java.util.Date;
import java.util.List;

@Data
@Builder
@RequiredArgsConstructor
@AllArgsConstructor
public class GeneralResponse implements Response {
    private String message;
    private Date timeStamp;
    private List<UserResponse> userResponseList;

}

