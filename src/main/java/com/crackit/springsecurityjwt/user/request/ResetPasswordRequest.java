package com.crackit.springsecurityjwt.user.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@RequiredArgsConstructor
public class ResetPasswordRequest {
    private String newPassword;
    private String confirmPassword;
}
