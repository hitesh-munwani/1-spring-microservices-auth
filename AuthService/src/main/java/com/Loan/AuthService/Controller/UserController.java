package com.Loan.AuthService.Controller;

import com.Loan.AuthService.Model.User;
import com.Loan.AuthService.Service.UserService;
import com.Loan.AuthService.jwtUtils.JwtResponse;
import com.Loan.AuthService.jwtUtils.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);
    @Autowired
    private UserService userService;
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User user) {
        try {
            logger.info("Attempting to authenticate user: {}", user.getUsername());
            Authentication authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
            if (authenticate.isAuthenticated()) {
                String token = jwtUtil.generateToken(String.valueOf(user.getUsername()));
                //save refresh token
                userService.saveRefreshToken(user.getUsername(), jwtUtil.generateRefreshToken(user.getUsername()));

                logger.info("User authenticated successfully: {}", user.getUsername());
                return ResponseEntity.ok(new JwtResponse(token, jwtUtil.generateRefreshToken(user.getUsername())));
            }
        } catch (UsernameNotFoundException e) {
            logger.error("User not found: {}", user.getUsername());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not found");
        } catch (BadCredentialsException e) {
            logger.error("Invalid username/password for user: {}", user.getUsername());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid username/password");
        } catch (Exception e) {
            logger.error("Login failed for user: {}", user.getUsername(), e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Login Failed");
        }
        logger.error("Login failed for user: {}", user.getUsername());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Login Failed");
    }

    @PostMapping("/register")
    public ResponseEntity<?> save(@RequestBody User user) { // Create User
        if (userService.findByUserName(user.getUsername()) != null) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("User already exists");
        }
        return ResponseEntity.ok(userService.createUser(user));
    }


    @PostMapping("/refresh")
    public ResponseEntity<?> refreshAccessToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        String newAccessToken = jwtUtil.refreshAccessToken(refreshToken);
        return ResponseEntity.ok(Collections.singletonMap("accessToken", newAccessToken));
    }

    //make a get mapping to get all users
    @GetMapping("/get")
    public ResponseEntity<?> getAllUsers() {
        return ResponseEntity.ok(userService.getUser());
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");

        if (refreshToken == null || refreshToken.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Collections.singletonMap("error", "Refresh token is required"));
        }
        boolean isRevoked = userService.revokeToken(refreshToken);
        if (isRevoked) {
            return ResponseEntity.ok(Collections.singletonMap("message", "Logged out successfully"));
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Collections.singletonMap("error", "Invalid or expired token"));
        }
    }
}