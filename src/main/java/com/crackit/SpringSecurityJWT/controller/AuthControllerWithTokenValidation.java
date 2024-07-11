package com.crackit.SpringSecurityJWT.controller;

import com.crackit.SpringSecurityJWT.constant.AppConstants;
import com.crackit.SpringSecurityJWT.service.JwtService;
import com.crackit.SpringSecurityJWT.user.reponse.GeneralResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;

@RestController
@RequestMapping(AppConstants.TEST_ENDPOINT)
@RequiredArgsConstructor
@SecurityRequirement(name = AppConstants.SECURITY_REQUIRED_BEARERAUTH)
public class AuthControllerWithTokenValidation {

    private final JwtService jwtService;
    private static final Logger logger = LoggerFactory.getLogger(AuthControllerWithTokenValidation.class);

    @GetMapping(AppConstants.TEST_PROTECTED_ENDPOINT)
    public ResponseEntity<?> accessProtectedResource(HttpServletRequest httpServletRequest) {
        String authHeader = httpServletRequest.getHeader(AppConstants.HEADER_STRING);
        System.out.println("authHeader : " + authHeader);
        String token = extractToken(authHeader);
        System.out.println("token in main controller : " + token);
        if (token == null) {
            return createResponse(AppConstants.TEST_NO_TOKEN_PROVIDED, HttpStatus.UNAUTHORIZED);
        }

        String userName = jwtService.extractUserName(token);
        logger.info("Token: {}, UserName: {}", token, userName);

        try {
            if (jwtService.isTokenValidOrNot(token, userName)) {
                return createResponse(AppConstants.TEST_ACCESS_GRANTED, HttpStatus.OK);
            } else {
                return createResponse(AppConstants.TEST_INVALID_TOKEN, HttpStatus.UNAUTHORIZED);
            }
        } catch (Exception e) {
            logger.error("Token verification failed", e);
            return createResponse(AppConstants.TEST_TOKEN_VERIFICATION_FAILED, HttpStatus.UNAUTHORIZED);
        }
    }

    private String extractToken(String tokenHeader) {
        if (tokenHeader != null && tokenHeader.startsWith(AppConstants.TOKEN_PREFIX)) {
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