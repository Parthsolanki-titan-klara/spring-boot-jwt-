package com.crackit.springsecurityjwt.service.user;

import com.crackit.springsecurityjwt.cache.LRUCache;
import com.crackit.springsecurityjwt.constant.Constant;
import com.crackit.springsecurityjwt.user.User;
import com.crackit.springsecurityjwt.user.UserRepository;
import com.crackit.springsecurityjwt.user.reponse.Response;
import com.crackit.springsecurityjwt.user.reponse.ResponseUtil;
import com.crackit.springsecurityjwt.user.reponse.UserResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final LRUCache<String, User> userCache = new LRUCache<>(100000);

    public ResponseEntity<Response> getUserByEmail(String email) {
        User user = null;
        try {
            user = userCache.get(email);
            System.out.println("User from cache: " + user);
            if (user == null) {
                user = userRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found"));
                System.out.println("User from db: " + user);
                userCache.put(email, user);
            }
        } catch (RuntimeException e) {
            return ResponseUtil.createResponse(Constant.USER_NOT_FOUND, HttpStatus.NOT_FOUND);
        }

        return ResponseEntity.ok(UserResponse.builder()
                .id(user.getId())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .email(user.getEmail())
                .userRole(user.getUserRole())
                .build());
    }

    public ResponseEntity<Response> getAllUsers() {
        List<User> users = userRepository.findAll();
        List<UserResponse> userResponses = users.stream()
                .map(user -> UserResponse.builder()
                        .id(user.getId())
                        .firstName(user.getFirstName())
                        .lastName(user.getLastName())
                        .email(user.getEmail())
                        .userRole(user.getUserRole())
                        .build())
                .collect(Collectors.toList());

        userResponses.forEach(userResponse -> System.out.println("User: " + userResponse));

        return ResponseUtil.createListResponse(userResponses, Constant.USERS_FETCHED, HttpStatus.OK);
    }
}
