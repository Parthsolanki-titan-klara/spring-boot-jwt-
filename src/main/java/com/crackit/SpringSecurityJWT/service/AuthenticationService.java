package com.crackit.SpringSecurityJWT.service;

import com.crackit.SpringSecurityJWT.user.User;
import com.crackit.SpringSecurityJWT.user.UserRepository;
import com.crackit.SpringSecurityJWT.user.reponse.GeneralResponse;
import com.crackit.SpringSecurityJWT.user.request.RegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

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

                    com.crackit.SpringSecurityJWT.user.reponse.AuthenticationService authResponse = new com.crackit.SpringSecurityJWT.user.reponse.AuthenticationService(jwtToken);
                    responseEntity[0] = ResponseEntity.ok(authResponse);
                });

        return responseEntity[0];
    }


    /**
     * Login a user if the user exists and the password is correct return a jwt token else return null
     *
     * @param username
     * @param password
     * @return
     */
    public String loginUser(String username, String password) {
        return userRepository.findByEmail(username)
                .filter(user -> passwordEncoder.matches(password, user.getPassword()))
                .map(user -> jwtService.generateToken(user))
                .orElse(null);
    }

}
