package com.Loan.AuthService.controller;

import com.Loan.AuthService.model.User;
import com.Loan.AuthService.service.UserService;
import com.Loan.AuthService.jwtUtils.JwtResponse;
import com.Loan.AuthService.jwtUtils.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class UserController {

    @Autowired
    private UserService userService; // Service layer to handle user-related operations

    @Autowired
    private AuthenticationManager authenticationManager; // Manages authentication process

    @Autowired
    private JwtUtil jwtUtil; // Utility class for JWT token management

    // Logger for logging important events and errors
    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    /**
     * Handles user login and authentication.
     * If authentication is successful, it generates an access token and a refresh token.
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User user) {
        try {
            logger.info("Attempting to authenticate user: {}", user.getUsername());

            // Authenticate user using username and password
            Authentication authenticate = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword())
            );

            if (authenticate.isAuthenticated()) {
                // Generate JWT access and refresh tokens
                String token = jwtUtil.generateToken(user.getUsername());
                String refreshToken = jwtUtil.generateRefreshToken(user.getUsername());

                // Save refresh token in the database
                userService.saveRefreshToken(user.getUsername(), refreshToken);

                logger.info("User authenticated successfully: {}", user.getUsername());
                return ResponseEntity.ok(new JwtResponse(token, refreshToken));
            }
        } catch (UsernameNotFoundException | BadCredentialsException e) {
            logger.error("Authentication failed for user: {}", user.getUsername(), e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        } catch (Exception e) {
            logger.error("Login failed for user: {}", user.getUsername(), e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Login Failed");
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Login Failed");
    }

    /**
     * Registers a new user in the system.
     * If the username already exists, it returns a conflict response.
     */
    @PostMapping("/register")
    public ResponseEntity<?> save(@RequestBody User user) {
        if (userService.findByUserName(user.getUsername()) != null) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("User already exists");
        }
        return ResponseEntity.ok(userService.createUser(user));
    }

    /**
     * Refreshes the access token using a valid refresh token.
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshAccessToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        String newAccessToken = jwtUtil.refreshAccessToken(refreshToken);
        return ResponseEntity.ok(Collections.singletonMap("accessToken", newAccessToken));
    }

    /**
     * Retrieves all registered users from the system.
     */
    @GetMapping("/get")
    public ResponseEntity<?> getAllUsers() {
        return ResponseEntity.ok(userService.getUser());
    }

    /**
     * Logs out the user by revoking the refresh token.
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");

        // Check if refresh token is provided
        if (refreshToken == null || refreshToken.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Collections.singletonMap("error", "Refresh token is required"));
        }

        // Attempt to revoke the token
        boolean isRevoked = userService.revokeToken(refreshToken);
        if (isRevoked) {
            return ResponseEntity.ok(Collections.singletonMap("message", "Logged out successfully"));
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("error", "Invalid or expired token"));
        }
    }
}
