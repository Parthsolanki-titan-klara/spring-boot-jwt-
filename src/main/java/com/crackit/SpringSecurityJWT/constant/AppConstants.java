package com.crackit.SpringSecurityJWT.constant;

public class AppConstants {

    //JWT constants
    public static final String JWT_SECRET_KEY = "fe7bd3291f24181c41da266c8ecacb8b949fa55610f32f7f165ad05a9c431623";
    public static final long JWT_EXPIRATION = 60000; // 1 minute
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String HEADER_STRING = "Authorization";
    public static final String SECURITY_REQUIRED_BEARERAUTH = "bearerAuth";

    // Security constants
    public static final String SECURITY_STRING_MATCHER = "/api/v1/auth/**";

    //API Respponse constants
    public static final String RESPONSE_MEDIA_TYPE = "application/json";
    public static final String REGISTER_RESPONSE_DESCRIPTION = "Successfully registered";
    public static final String LOGIN_RESPONSE_DESCRIPTION = "Successfully logged in";
    public static final String REGISTER_API_RESPONSE = "{\"token\":\"765677868767567547836432678278478234\"}";
    public static final String LOGIN_API_RESPONSE = "{\"token\":\"765677868767567547836432678278478234\", \"email\":\"user@example.com\"}";
    public static final String TEST_NO_TOKEN_PROVIDED = "No token provided";
    public static final String TEST_ACCESS_GRANTED = "Access granted to protected resource";
    public static final String TEST_INVALID_TOKEN = "Invalid token";
    public static final String TEST_TOKEN_VERIFICATION_FAILED = "Token verification failed";

    // STATUS CODES
    public static final String STATUS_OK = "OK";
    public static final String STATUS_UNAUTHORIZED = "UNAUTHORIZED";
    public static final String STATUS_FORBIDDEN = "FORBIDDEN";
    public static final String STATUS_NOT_FOUND = "NOT_FOUND";
    public static final String STATUS_INTERNAL_SERVER_ERROR = "INTERNAL_SERVER_ERROR";
    public static final String STATUS_BAD_REQUEST = "BAD_REQUEST";
    public static final String STATUS_CREATED = "CREATED";
    public static final String STATUS_NO_CONTENT = "NO_CONTENT";
    public static final String STATUS_ACCEPTED = "ACCEPTED";

    // Register constants
    public static final String REGISTER_ENDPOINT = "/api/v1/auth/register";

    //Login constants
    public static final String LOGIN_ENDPOINT = "/api/v1/login";

    // test controller constants
    public static final String TEST_ENDPOINT = "/api/v1/test";
    public static final String TEST_PROTECTED_ENDPOINT = "/protected";

    // Swagger constants
    public static final String SWAGGER_REGISTER_LOGIN_TAG_NAME = "Register and Login documents";
    public static final String SWAGGER_REGISTER_LOGIN_TAG_DESCRIPTION = "Register and Login documents service";

    //Exception constants
    public static final String USER_NOT_FOUND = "User not found";
    public static final String USER_ALREADY_EXISTS = "User already exists";
    public static final String INVALID_CREDENTIALS = "Invalid credentials";
    public static final String AUTH_FAILED = "Authentication failed";

    public static final String MESSAGE = "message";
    public static final String EMAIL = "email";
    public static final String TOKEN = "token";
}
