package com.crackit.SpringSecurityJWT.service;

import com.crackit.SpringSecurityJWT.cache.LRUCache;
import com.crackit.SpringSecurityJWT.user.User;
import com.crackit.SpringSecurityJWT.user.UserRepository;
import com.crackit.SpringSecurityJWT.user.reponse.GeneralResponse;
import com.crackit.SpringSecurityJWT.user.request.RegisterRequest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Map;

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
    public ResponseEntity<?> register(RegisterRequest registerRequest) {
        final ResponseEntity<?>[] responseEntity = new ResponseEntity[1];
        userRepository.findByEmail(registerRequest.getEmail())
                .ifPresentOrElse(user -> {
                    GeneralResponse response = GeneralResponse.builder()
                            .message("User already exists")
                            .timeStamp(new Date(System.currentTimeMillis()))
                            .build();
                    responseEntity[0] = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
                }, () -> {
                    // User does not exist, proceed with registration
                    User newUser = User.builder()
                            .firstName(registerRequest.getFirstName())
                            .lastName(registerRequest.getLastName())
                            .email(registerRequest.getEmail())
                            .password(passwordEncoder.encode(registerRequest.getPassword()))
                            .userRole(registerRequest.getRole())
                            .build();
                    String jwtToken = jwtService.generateToken(newUser);
                    newUser.setToken(jwtToken);
                    userRepository.save(newUser);

                    System.out.println("New User: " + newUser);

                    // Cache the user
                    userCache.put(registerRequest.getEmail(), newUser);

                    User cachedUser = userCache.get(registerRequest.getEmail());

                    System.out.println("Cache: " + userCache);
                    System.out.println("Cached User: " + cachedUser);

                    GeneralResponse authResponse = GeneralResponse.builder()
                            .message(jwtToken)
                            .timeStamp(new Date(System.currentTimeMillis()))
                            .build();
                    responseEntity[0] = ResponseEntity.ok(authResponse);
                });

        return responseEntity[0];
    }


    /**
     * Login a user if the user exists and the password is correct return a jwt token else return null
     *
     * @param email
     * @param password
     * @return
     */
//    public String loginUser(String username, String password) {
//
//        // check if the user is in the cache then no need to hit the database
//        if(userCache.containsKey(username)){
//            User user = userCache.get(username);
//            if(passwordEncoder.matches(password, user.getPassword())){
//                return jwtService.generateToken(user);
//            }
//        }
//        return null;
//    }

    public ResponseEntity<?> loginUser(String email, String password) throws JsonProcessingException {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, password)
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        if (authentication.isAuthenticated()) {
            User cachedUser = userCache.get(email);
            System.out.println("User Cache: " + cachedUser);
            // check if the user is in the cache then no need to hit the database
            if(userCache.containsKey(email)){
                User user = userCache.get(email);
                if(passwordEncoder.matches(password, user.getPassword())){
                    String token = jwtService.generateToken(user);
                    Map<String, String> payload = Map.of("email", email, "token", token);
                    return ResponseEntity.ok(new GeneralResponse(new ObjectMapper().writeValueAsString(payload), new Date(System.currentTimeMillis())));
                }
            }
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new GeneralResponse("Authentication failed", new Date()));
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new GeneralResponse("Authentication failed", new Date()));
    }
}
