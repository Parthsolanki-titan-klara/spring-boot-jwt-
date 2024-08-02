package com.crackit.springsecurityjwt.user.reponse;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;

import java.util.Date;

@Data
@Builder
@RequiredArgsConstructor
@AllArgsConstructor
public class GeneralResponse implements Response {
    private String message;
    private Date timeStamp;

}
