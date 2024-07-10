package com.crackit.SpringSecurityJWT.controller;

import com.crackit.SpringSecurityJWT.service.AuthenticationService;
import com.crackit.SpringSecurityJWT.service.JwtService;
import com.crackit.SpringSecurityJWT.user.reponse.GeneralResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;

@RestController
@RequestMapping("/api/v1/test")
@RequiredArgsConstructor
public class AuthControllerWithTokenValidation {

    private final AuthenticationService authenticationService;
    private final JwtService jwtService;
    private static final Logger logger = LoggerFactory.getLogger(AuthControllerWithTokenValidation.class);

    @GetMapping("/protected")
    public ResponseEntity<?> accessProtectedResource(@RequestHeader("Authorization") String tokenHeader) {
        String token = extractToken(tokenHeader);
        System.out.println("token in main controller : " + token);
        if (token == null) {
            return createResponse("No token provided", HttpStatus.UNAUTHORIZED);
        }

        String userName = jwtService.extractUserName(token);
        logger.info("Token: {}, UserName: {}", token, userName);

        try {
            if (jwtService.isTokenValidOrNot(token, userName)) {
                return createResponse("Access granted to protected resource", HttpStatus.OK);
            } else {
                return createResponse("Invalid token", HttpStatus.UNAUTHORIZED);
            }
        } catch (Exception e) {
            logger.error("Token verification failed", e);
            return createResponse("Token verification failed", HttpStatus.UNAUTHORIZED);
        }
    }

    private String extractToken(String tokenHeader) {
        if (tokenHeader != null && tokenHeader.startsWith("Bearer ")) {
            String token = tokenHeader.substring(7);
            System.out.println("Extract token : " + token);
            return token;
        }
        return null;
    }

    private ResponseEntity<GeneralResponse> createResponse(String message, HttpStatus status) {
        GeneralResponse response = new GeneralResponse(message, new Date());
        System.out.println("response : " + response);
        return new ResponseEntity<>(response, status);
    }
}