package com.crackit.springsecurityjwt.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.crackit.springsecurityjwt.service.AuthenticationService;
import com.crackit.springsecurityjwt.service.JwtService;
import com.crackit.springsecurityjwt.user.reponse.Response;
import com.crackit.springsecurityjwt.user.reponse.ResponseUtil;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/test")
@RequiredArgsConstructor
@SecurityRequirement(name = "bearerAuth")
public class AuthControllerWithTokenValidation {

    private final JwtService jwtService;
    private static final Logger logger = LoggerFactory.getLogger(AuthControllerWithTokenValidation.class);

    @GetMapping("/protected")
    public ResponseEntity<Response> accessProtectedResource(HttpServletRequest httpServletRequest) {
        String authHeader = httpServletRequest.getHeader("Authorization");
        System.out.println("authHeader : " + authHeader);
        String token = extractToken(authHeader);
        System.out.println("token in main controller : " + token);
        if (token == null) {
            return ResponseUtil.createResponse("No token provided", HttpStatus.UNAUTHORIZED);
        }
        DecodedJWT jwt = JWT.decode(token);
        String userName = jwt.getClaim("email").asString();


//        String userName = jwtService.extractUserName(token);
        logger.info("Token: {}, UserName: {}", token, userName);

        try {
            Boolean isUserAuthenticated = jwtService.isTokenValidOrNot(token, userName);
            if (isUserAuthenticated) {
                return ResponseUtil.createResponse("Access granted to protected resource", HttpStatus.OK);
            } else {
                return ResponseUtil.createResponse("Invalid token", HttpStatus.UNAUTHORIZED);
            }
        } catch (Exception e) {
            logger.error("Token verification failed", e);
            return ResponseUtil.createResponse("Token verification failed", HttpStatus.UNAUTHORIZED);
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
}