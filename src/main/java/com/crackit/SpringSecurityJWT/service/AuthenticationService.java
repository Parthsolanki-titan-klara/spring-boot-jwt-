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
    public Map<String,String> register(RegisterRequest registerRequest) {
        Optional<User> existingUser = userRepository.findByEmail(registerRequest.getEmail());
        Map<String, String> response;
        if (existingUser.isPresent()) {
            response = Map.of("message", "User already exists");
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
            newUser.setToken(jwtToken);
            userRepository.save(newUser);

            System.out.println("New User: " + newUser);

            // Cache the user
            userCache.put(registerRequest.getEmail(), newUser);

            User cachedUser = userCache.get(registerRequest.getEmail());

            System.out.println("Cached User at register time : " + cachedUser);
            response = Map.of("token", jwtToken);
            return response;
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
    public Map<String, String> loginUser(String email, String password) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, password)
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        if (authentication.isAuthenticated()) {
            // check if the user is in the cache then no need to hit the database
            if(userCache.containsKey(email)){
                User cachedUser = userCache.get(email);
                System.out.println("Cached User at login time : " + cachedUser);
                String token = cachedUser.getToken();
                if(passwordEncoder.matches(password, cachedUser.getPassword())){
                    return Map.of("email", email, "token", token);
                }
            }
        } else {
            return Map.of("message", "Authentication failed");
        }
        return Map.of("message", "Authentication failed");
    }
}
