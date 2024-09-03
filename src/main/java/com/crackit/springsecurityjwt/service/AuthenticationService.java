package com.crackit.springsecurityjwt.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.crackit.springsecurityjwt.cache.LRUCache;
import com.crackit.springsecurityjwt.constant.Constant;
import com.crackit.springsecurityjwt.controller.AuthController;
import com.crackit.springsecurityjwt.controller.AuthControllerWithTokenValidation;
import com.crackit.springsecurityjwt.user.User;
import com.crackit.springsecurityjwt.user.UserRepository;
import com.crackit.springsecurityjwt.user.reponse.*;
import com.crackit.springsecurityjwt.user.request.RegisterRequest;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;


    private final LRUCache<String , User> userCache = new LRUCache<>(100000);

    /**
     * Register a new user if the user already exists return a bad request response else return an ok response with the jwt token
     *
     * @param registerRequest
     * @return
     */
    public ResponseEntity<Response> register(RegisterRequest registerRequest) {
        Optional<User> existingUser = userRepository.findByEmail(registerRequest.getEmail());
        ResponseEntity<Response> response;
        if (existingUser.isPresent()) {
            response = ResponseUtil.createResponse(Constant.USER_ALREADY_EXISTS, HttpStatus.BAD_REQUEST);
        } else {
            // User does not exist, proceed with registration
            User newUser = User.builder()
                    .firstName(registerRequest.getFirstName())
                    .lastName(registerRequest.getLastName())
                    .email(registerRequest.getEmail())
                    .password(passwordEncoder.encode(registerRequest.getPassword()))
                    .userRole(registerRequest.getRole())
                    .build();
            String jwtToken = jwtService.generateToken(newUser);
            String refreshJwtToken = jwtService.generateRefreshToken(newUser);
            newUser.setToken(jwtToken);
            newUser.setRefreshToken(refreshJwtToken);
            userRepository.save(newUser);

            System.out.println("New User: " + newUser);

            // Cache the user
            userCache.put(registerRequest.getEmail(), newUser);

            User cachedUser = userCache.get(registerRequest.getEmail());

            System.out.println("Cached User at register time : " + cachedUser);
            return ResponseEntity.ok(new AuthResponse(jwtToken, refreshJwtToken));

        }
        return response;
    }


    /**
     * Login a user if the user exists and the password is correct return a jwt token else return null
     *
     * @param email
     * @param password
     * @return
     */
    public ResponseEntity<Response> loginUser(String email, String password) {
        ResponseEntity<Response> response;
        System.out.println("User Cache : " + userCache);

        // Check if the user is in the cache before attempting to authenticate
        if (!userCache.containsKey(email)) {
            response = ResponseUtil.createResponse(Constant.NOT_REGISTERED_USER, HttpStatus.UNAUTHORIZED);
            return response;
        }

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, password)
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);

            if (authentication.isAuthenticated()) {
                User cachedUser = userCache.get(email);
                System.out.println("Cached User at login time : " + cachedUser);
                String accessToken = cachedUser.getToken();
                String refreshToken = cachedUser.getRefreshToken();
                if (passwordEncoder.matches(password, cachedUser.getPassword())) {

                    response = ResponseEntity.ok(new LoginResponse(email, accessToken, refreshToken));
                } else {
                    response = ResponseUtil.createResponse(Constant.INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED);
                }
            } else {
                response = ResponseUtil.createResponse(Constant.INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED);
            }
        } catch (AuthenticationException e) {
            response = ResponseUtil.createResponse(Constant.INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED);
        }

        return response;
    }

    public ResponseEntity<Response> updatePassword(String newPassword , String confirmPassword) {

        if (!newPassword.equals(confirmPassword)) {
            return ResponseUtil.createResponse(Constant.PASSWORD_NOT_MATCHED, HttpStatus.BAD_REQUEST);
        }
        // Get the authenticated user's email
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        System.out.println("Email : " + email);

        // Fetch the user from the database
        Optional<User> optionalUser = userRepository.findByEmail(email);
        if (optionalUser.isEmpty()) {
            return ResponseUtil.createResponse(Constant.USER_NOT_FOUND, HttpStatus.NOT_FOUND);
        }

        User user = optionalUser.get();

        // Update the user's password
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        System.out.println("Saved User : " + user);

        // Update the user in the cache
        userCache.put(email, user);
        System.out.println("Updated User in cache : " + userCache.get(email));

        return ResponseEntity.ok(new GeneralResponse(Constant.PASSWORD_RESET_SUCCESS, new Date(), null));
    }

    public ResponseEntity<Response> refreshToken(String token) {

        String refreshToken = extractToken(token);
        System.out.println("Refresh token when api call : " + refreshToken);
        if (refreshToken == null) {
            return ResponseUtil.createResponse("No refresh token provided", HttpStatus.UNAUTHORIZED);
        }

        if (jwtService.isTokenExpired(refreshToken)) {
            return ResponseUtil.createResponse("Refresh token expired", HttpStatus.UNAUTHORIZED);
        }

        DecodedJWT jwt = JWT.decode(refreshToken);
        String userName = jwt.getClaim("sub").asString();
        System.out.println("User Name : " + userName);
//        String userName = jwtService.extractUserName(refreshToken);
        Optional<User> optionalUser = userRepository.findByEmail(userName);

        if (optionalUser.isEmpty()) {
            return ResponseUtil.createResponse("User not found", HttpStatus.NOT_FOUND);
        }

        User user = optionalUser.get();
        String newAccessToken = jwtService.generateToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user);

        user.setToken(newAccessToken);
        user.setRefreshToken(newRefreshToken);
        userRepository.save(user);

        userCache.put(userName, user);

        return ResponseEntity.ok(new AuthResponse(newAccessToken, newRefreshToken));
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

