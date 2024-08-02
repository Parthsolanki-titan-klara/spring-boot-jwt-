package com.crackit.springsecurityjwt.user.reponse;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@Builder
@RequiredArgsConstructor
@AllArgsConstructor
public class LoginResponse implements Response {
    private String email;
    private String accessToken;
    private String refreshToken;
}
