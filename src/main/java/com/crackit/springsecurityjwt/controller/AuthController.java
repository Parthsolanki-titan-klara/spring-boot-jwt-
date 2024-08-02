package com.crackit.springsecurityjwt.controller;

import com.crackit.springsecurityjwt.service.AuthenticationService;
import com.crackit.springsecurityjwt.user.reponse.GeneralResponse;
import com.crackit.springsecurityjwt.user.reponse.Response;
import com.crackit.springsecurityjwt.user.request.LoginRequest;
import com.crackit.springsecurityjwt.user.request.RegisterRequest;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@Tag(name = "Register and Login documents",
        description = "Register and Login documents service")
public class AuthController {

    private final AuthenticationService authenticationService;

    @PostMapping("/api/v1/login")
    @ApiResponse(
            responseCode = "200",
            description = "Successfully logged In",
            content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(
                            value = "{\"token\":\"765677868767567547836432678278478234\", \"email\":\"user@example.com\"}"
                    )
            )
    )
    public ResponseEntity<Response> login(@RequestBody LoginRequest loginRequest) {
        return authenticationService.loginUser(loginRequest.getEmail(), loginRequest.getPassword());
    }

    @PostMapping(value = "api/v1/register", consumes = "application/json", produces = "application/json")
    @ApiResponse(
            responseCode = "200",
            description = "Successfully registered",
            content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(
                            value = "{\"token\":\"765677868767567547836432678278478234\"}"
                    )
            )
    )
    public ResponseEntity<Response> register(
            @RequestBody RegisterRequest authenticationRequest
    ) {
        System.out.println("Registering user");
        return authenticationService.register(authenticationRequest);
    }
}
