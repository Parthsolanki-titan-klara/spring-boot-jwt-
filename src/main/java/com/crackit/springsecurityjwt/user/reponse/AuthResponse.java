package com.crackit.springsecurityjwt.user.reponse;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@Builder
@RequiredArgsConstructor
@AllArgsConstructor
public class AuthResponse implements Response {
    private String accessToken;
    private String refreshToken;
}
