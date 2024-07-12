package com.crackit.SpringSecurityJWT.service;

import com.crackit.SpringSecurityJWT.cache.LRUCache;
import com.crackit.SpringSecurityJWT.constant.AppConstants;
import com.crackit.SpringSecurityJWT.user.User;
import com.crackit.SpringSecurityJWT.user.UserRepository;
import com.crackit.SpringSecurityJWT.user.request.RegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
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
//     */

    public Map<String,String> register(RegisterRequest registerRequest) {
        Optional<User> existingUser = userRepository.findByEmail(registerRequest.getEmail()); // TODO: Check if the user exists in the cache first
        Map<String, String> response;
        if (existingUser.isPresent()) {
            response = Map.of(AppConstants.MESSAGE, AppConstants.USER_ALREADY_EXISTS);
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
            response = Map.of(AppConstants.TOKEN, jwtToken);
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
                    return Map.of(AppConstants.EMAIL, email, AppConstants.TOKEN, token);
                }
            }
        } else {
            return Map.of(AppConstants.MESSAGE, AppConstants.AUTH_FAILED);
        }
        return Map.of(AppConstants.MESSAGE, AppConstants.AUTH_FAILED);
    }
}
