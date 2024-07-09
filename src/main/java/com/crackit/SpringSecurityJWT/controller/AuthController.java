package com.crackit.SpringSecurityJWT.controller;

import com.crackit.SpringSecurityJWT.service.AuthenticationService;
import com.crackit.SpringSecurityJWT.user.reponse.AuthentoictionResponse;
import com.crackit.SpringSecurityJWT.user.reponse.GeneralResponse;
import com.crackit.SpringSecurityJWT.user.request.LoginRequest;
import com.crackit.SpringSecurityJWT.user.request.RegisterRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationService authenticationService;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/login")
    public ResponseEntity<GeneralResponse> login(@RequestBody LoginRequest loginRequest) {
        try {
            System.out.println("login email : " + loginRequest.getEmail());
            System.out.println("login password : " + loginRequest.getPassword());
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword())
            );
            if (authentication.isAuthenticated()) {
                String email = authentication.getName();
                String token = authenticationService.loginUser(email, loginRequest.getPassword());
                Map<String, String> payload = Map.of("email", authentication.getName(), "token", token);
                System.out.println("payload : " + payload);
                return ResponseEntity.ok(new GeneralResponse(new ObjectMapper().writeValueAsString(payload), new Date(System.currentTimeMillis())));

            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new GeneralResponse("Authentication failed", new Date()));

            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new GeneralResponse("Bad credentials", new Date()));

        }
    }

    @PostMapping("/register")
    public ResponseEntity<AuthentoictionResponse> register(
            @RequestBody RegisterRequest authenticationRequest
    ) {
        System.out.println("Registering user");
        return ResponseEntity.ok(authenticationService.register(authenticationRequest));
    }

    // create another api which is accessible using the token



}
