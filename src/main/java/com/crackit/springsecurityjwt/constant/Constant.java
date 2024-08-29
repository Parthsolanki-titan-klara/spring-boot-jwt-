package com.crackit.springsecurityjwt.constant;

public class Constant {
    public static final String INVALID_CREDENTIALS = "Invalid credentials";
    public static final String NOT_REGISTERED_USER = "User not registered. Please register first.";
    public static final String WRONG_EMAIL_ID = "Email id is wrong";
    public static final String WRONG_PASSWORD = "Password is wrong";
    public static final String USER_NOT_FOUND = "User not found";
    public static final String USER_ALREADY_EXISTS = "User already exists";
    public static final String PASSWORD_RESET_SUCCESS = "Password reset successful";
    public static final String PASSWORD_NOT_MATCHED = "Passwords do not match";
    public static final String ACCESS_DENIED = "Access denied";
    public static final String NO_TOKEN_PROVIDED = "No token provided";
    public static final String USERS_FETCHED = "Users fetched successfully";
    // Private constructor to prevent instantiation
    private Constant() {
        throw new UnsupportedOperationException("Constant class should not be instantiated");
    }
}
