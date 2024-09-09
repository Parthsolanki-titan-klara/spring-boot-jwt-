package com.crackit.springsecurityjwt.user.reponse;

import com.crackit.springsecurityjwt.user.UserRole;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@Builder
@RequiredArgsConstructor
@AllArgsConstructor
public class RegisterResponse implements Response {
    private String firstName;
    private String lastName;
    private String email;
    private UserRole role;
}