package com.crackit.springsecurityjwt.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.crackit.springsecurityjwt.service.AuthenticationService;
import com.crackit.springsecurityjwt.service.JwtService;
import com.crackit.springsecurityjwt.user.User;
import com.crackit.springsecurityjwt.user.reponse.GeneralResponse;
import com.crackit.springsecurityjwt.user.reponse.Response;
import com.crackit.springsecurityjwt.user.reponse.ResponseUtil;
import com.crackit.springsecurityjwt.user.request.LoginRequest;
import com.crackit.springsecurityjwt.user.request.RegisterRequest;
import com.crackit.springsecurityjwt.user.request.ResetPasswordRequest;
import io.jsonwebtoken.Claims;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@Tag(name = "Register and Login documents",
        description = "Register and Login documents service")
public class AuthController {

    private final AuthenticationService authenticationService;
    private final JwtService jwtService;
//    @CrossOrigin(origins = "http://localhost:3000", allowedHeaders = "*")
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

//    @CrossOrigin(origins = "http://localhost:3000", allowedHeaders = "*")
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

    @PostMapping(value = "/api/v1/reset-password", consumes = "application/json", produces = "application/json")
    @ApiResponse(
            responseCode = "200",
            description = "Password successfully reset",
            content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(
                            value = "{\"message\":\"Password reset successful\"}"
                    )
            )
    )
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<Response> resetPassword(@RequestBody ResetPasswordRequest resetPasswordRequest, HttpServletRequest httpServletRequest) {
        String authHeader = httpServletRequest.getHeader("Authorization");
        System.out.println("authHeader : " + authHeader);
        String token = extractToken(authHeader);
        System.out.println("token in main controller : " + token);
        if (token == null) {
            return ResponseUtil.createResponse("No token provided", HttpStatus.UNAUTHORIZED);
        }
        DecodedJWT jwt = JWT.decode(token);
        String userName = jwt.getSubject();
//        String userName = jwtService.extractUserName(token);
        System.out.println("Token: " + token + ", UserName: " + userName);

        return  authenticationService.updatePassword(resetPasswordRequest.getNewPassword() , resetPasswordRequest.getConfirmPassword());

    }

    // Add the following method to the `AuthController` class

    @PostMapping("/api/v1/refresh-token")
    @ApiResponse(
            responseCode = "200",
            description = "Successfully refreshed token",
            content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(
                            value = "{\"accessToken\":\"newAccessToken\", \"refreshToken\":\"newRefreshToken\"}"
                    )
            )
    )
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<Response> refreshToken(HttpServletRequest request) {
        String token = request.getHeader("Authorization");
        return authenticationService.refreshToken(token);
    }

    private String extractToken(String tokenHeader) {
        if (tokenHeader != null && tokenHeader.startsWith("Bearer ")) {
            String token = tokenHeader.substring(7);
            System.out.println("Extract token : " + token);
            return token;
        }
        return null;
    }
}
