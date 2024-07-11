package com.crackit.SpringSecurityJWT.controller;

import com.crackit.SpringSecurityJWT.constant.AppConstants;
import com.crackit.SpringSecurityJWT.service.AuthenticationService;
import com.crackit.SpringSecurityJWT.user.request.LoginRequest;
import com.crackit.SpringSecurityJWT.user.request.RegisterRequest;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@Tag(name = AppConstants.SWAGGER_REGISTER_LOGIN_TAG_NAME,
        description = AppConstants.SWAGGER_REGISTER_LOGIN_TAG_DESCRIPTION)
public class AuthController {

    private final AuthenticationService authenticationService;

    @PostMapping(AppConstants.LOGIN_ENDPOINT)
    @ApiResponse(
            responseCode = AppConstants.STATUS_OK,
            description = AppConstants.LOGIN_RESPONSE_DESCRIPTION,
            content = @Content(
                    mediaType = AppConstants.RESPONSE_MEDIA_TYPE,
                    examples = @ExampleObject(
                            value = AppConstants.LOGIN_API_RESPONSE
                    )
            )
    )
    public Map<String,String> login(@RequestBody LoginRequest loginRequest) {
        return authenticationService.loginUser(loginRequest.getEmail(), loginRequest.getPassword());
    }

    @PostMapping(value = AppConstants.REGISTER_ENDPOINT, consumes = AppConstants.RESPONSE_MEDIA_TYPE, produces = AppConstants.RESPONSE_MEDIA_TYPE)
    @ApiResponse(
            responseCode = AppConstants.STATUS_OK,
            description = AppConstants.REGISTER_RESPONSE_DESCRIPTION,
            content = @Content(
                    mediaType = AppConstants.RESPONSE_MEDIA_TYPE,
                    examples = @ExampleObject(
                            value = AppConstants.REGISTER_API_RESPONSE
                    )
            )
    )
    public Map<String, String> register(
            @RequestBody RegisterRequest authenticationRequest
    ) {
        System.out.println("Registering user");
        return authenticationService.register(authenticationRequest);
    }
}
