package com.crackit.SpringSecurityJWT.controller;

import com.crackit.SpringSecurityJWT.service.AuthenticationService;
import com.crackit.SpringSecurityJWT.user.reponse.GeneralResponse;
import com.crackit.SpringSecurityJWT.user.request.RegisterRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationService authenticationService;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/login")
    public ResponseEntity<GeneralResponse> login(@RequestHeader("Authorization") String authHeader) {
        try {
            if (authHeader != null && authHeader.startsWith("Basic ")) {
                String base64Credentials = authHeader.substring("Basic ".length()).trim();
                byte[] credDecoded = Base64.getDecoder().decode(base64Credentials);
                String credentials = new String(credDecoded, StandardCharsets.UTF_8);
                final String[] values = credentials.split(":", 2);

                String email = values[0];
                String password = values[1];

                Authentication authentication = authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(email, password)
                );
                SecurityContextHolder.getContext().setAuthentication(authentication);

                if (authentication.isAuthenticated()) {
                    String token = authenticationService.loginUser(email, password);
                    Map<String, String> payload = Map.of("email", email, "token", token);
                    return ResponseEntity.ok(new GeneralResponse(new ObjectMapper().writeValueAsString(payload), new Date(System.currentTimeMillis())));
                } else {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new GeneralResponse("Authentication failed", new Date()));
                }
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new GeneralResponse("Missing or invalid Authorization header", new Date()));
            }
        } catch (Exception e) {
            SecurityContextHolder.clearContext();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new GeneralResponse("Bad credentials", new Date()));
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(
            @RequestBody RegisterRequest authenticationRequest
    ) {
        System.out.println("Registering user");
        return ResponseEntity.ok(authenticationService.register(authenticationRequest));
    }
}