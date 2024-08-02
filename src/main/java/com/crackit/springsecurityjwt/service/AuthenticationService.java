package com.crackit.springsecurityjwt.service;

import com.crackit.springsecurityjwt.cache.LRUCache;
import com.crackit.springsecurityjwt.constant.Constant;
import com.crackit.springsecurityjwt.controller.AuthController;
import com.crackit.springsecurityjwt.controller.AuthControllerWithTokenValidation;
import com.crackit.springsecurityjwt.user.User;
import com.crackit.springsecurityjwt.user.UserRepository;
import com.crackit.springsecurityjwt.user.reponse.AuthResponse;
import com.crackit.springsecurityjwt.user.reponse.GeneralResponse;
import com.crackit.springsecurityjwt.user.reponse.LoginResponse;
import com.crackit.springsecurityjwt.user.reponse.Response;
import com.crackit.springsecurityjwt.user.request.RegisterRequest;
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
            response = createResponse(Constant.USER_ALREADY_EXISTS, HttpStatus.BAD_REQUEST);
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

        // Check if the user is in the cache before attempting to authenticate
        if (!userCache.containsKey(email)) {
            response = createResponse(Constant.NOT_REGISTERED_USER, HttpStatus.UNAUTHORIZED);
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
                    response = createResponse(Constant.INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED);
                }
            } else {
                response = createResponse(Constant.INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED);
            }
        } catch (AuthenticationException e) {
            response = createResponse(Constant.INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED);
        }

        return response;
    }


    public ResponseEntity<Response> createResponse(String message, HttpStatus status) {
        GeneralResponse response = new GeneralResponse(message, new Date());
        System.out.println("response : " + response);
        return new ResponseEntity<>(response, status);
    }
}
