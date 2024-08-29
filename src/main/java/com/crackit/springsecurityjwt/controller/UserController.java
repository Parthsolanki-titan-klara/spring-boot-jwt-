package com.crackit.springsecurityjwt.controller;

import com.crackit.springsecurityjwt.constant.Constant;
import com.crackit.springsecurityjwt.service.JwtService;
import com.crackit.springsecurityjwt.service.user.UserService;
import com.crackit.springsecurityjwt.user.reponse.Response;
import com.crackit.springsecurityjwt.user.reponse.ResponseUtil;
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

@RestController
@RequiredArgsConstructor
@Tag(name = "User documents",
        description = "User documents service")
public class UserController {

    private final JwtService jwtService;
    private final UserService userService;

    @GetMapping(value = "/api/v1/users", produces = "application/json")
    @ApiResponse(
            responseCode = "200",
            description = "User fetched successfully",
            content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(
                            value = "{\"message\":\"User fetched successfully\"}"
                    )
            )
    )
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<Response> fetchUserByEmail(@RequestParam String email, HttpServletRequest httpServletRequest) {
        String authHeader = httpServletRequest.getHeader("Authorization");
        System.out.println("authHeader : " + authHeader);
        String token = extractToken(authHeader);
        System.out.println("token in main controller : " + token);
        if (token == null) {
            return ResponseUtil.createResponse("No token provided", HttpStatus.UNAUTHORIZED);
        }

        String userName = jwtService.extractUserName(token);
        System.out.println("Token: " + token + ", UserName: " + userName);

        return userService.getUserByEmail(email);
    }
    private String extractToken(String tokenHeader) {
        if (tokenHeader != null && tokenHeader.startsWith("Bearer ")) {
            String token = tokenHeader.substring(7);
            System.out.println("Extract token : " + token);
            return token;
        }
        return null;
    }


    @GetMapping(value = "/api/v1/allusers", produces = "application/json")
    @ApiResponse(
            responseCode = "200",
            description = "All users fetched successfully",
            content = @Content(
                    mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = "{\n" +
                                            "  \"message\": \"Users fetched successfully\",\n" +
                                            "  \"timeStamp\": \"2024-08-24T09:35:50.872+00:00\",\n" +
                                            "  \"userResponseList\": [\n" + "\n]"+
                                            "}"
                            )
            )
    )
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<Response> fetchAllUsers(HttpServletRequest httpServletRequest) {
        String authHeader = httpServletRequest.getHeader("Authorization");
        System.out.println("authHeader : " + authHeader);
        String token = extractToken(authHeader);
        System.out.println("token in main controller : " + token);

        if (token == null) {
            return ResponseUtil.createResponse(Constant.NO_TOKEN_PROVIDED, HttpStatus.UNAUTHORIZED);
        }

        if (!jwtService.isUserAdmin(token)){
            return ResponseUtil.createResponse(Constant.ACCESS_DENIED, HttpStatus.FORBIDDEN);
        }
        return userService.getAllUsers();
    }
}