package com.crackit.SpringSecurityJWT.service;

import com.crackit.SpringSecurityJWT.user.User;
import com.crackit.SpringSecurityJWT.user.UserRepository;
import com.crackit.SpringSecurityJWT.user.UserRole;
import com.crackit.SpringSecurityJWT.user.reponse.AuthentoictionResponse;
import com.crackit.SpringSecurityJWT.user.request.RegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthentoictionResponse register(RegisterRequest registerRequest) {
        User user = User.builder()
                .firstName(registerRequest.getFirstName())
                .lastName(registerRequest.getLastName())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .userRole(registerRequest.getRole())
                .build();

        System.out.println("User registered");
        String jwtToken = jwtService
                .generateToken(user);
        user.setToken(jwtToken);
        userRepository.save(user);

        return new AuthentoictionResponse(jwtToken);
    }

    public String loginUser(String username, String password) {
        return userRepository.findByEmail(username)
                .filter(user -> passwordEncoder.matches(password, user.getPassword()))
                .map(user -> jwtService.generateToken(user))
                .orElse(null);


//        User user = userRepository.findByEmail(username).get();
//        if (passwordEncoder.matches(password, user.getPassword())) {
//            String token = user.getToken();
//            if (jwtService.isTokenValid(token,user)) {
//                System.out.println("User logged in");
//                return token;
//            }
//        }
//        return null;
    }

}
