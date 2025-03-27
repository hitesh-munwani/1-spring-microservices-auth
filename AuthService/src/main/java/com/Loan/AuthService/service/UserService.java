package com.Loan.AuthService.service;

import com.Loan.AuthService.model.RefreshToken;
import com.Loan.AuthService.model.User;
import com.Loan.AuthService.repository.UserRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.Loan.AuthService.repository.RefreshTokenRepository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;



@Service
public class UserService {
    @Autowired
    private UserRepo userRepo;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;
    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    public boolean revokeToken(String refreshToken) {
        Optional<RefreshToken> token = refreshTokenRepository.findByToken(refreshToken);
        if (token.isPresent()) {
            RefreshToken t = token.get();
            t.setRevoked(true);  // Mark token as revoked
            refreshTokenRepository.save(t);  // Save the updated token
            return true;
        }
        return false;  // Token not found
    }

    public void saveRefreshToken(String username, String refreshToken) {
        User user = userRepo.findByUsername(username);
        if (user != null) {
            RefreshToken token = new RefreshToken();
            token.setToken(refreshToken);
            token.setUser(user);
            token.setExpiryDate(Instant.now().plusSeconds(60)); // Set expiry date to 60 seconds from now
            refreshTokenRepository.save(token);
            logger.info("Refresh token saved for user: {}", username);
        } else {
            logger.error("User not found while saving refresh token: {}", username);
        }
    }
    public User createUser(User user)
    {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepo.save(user);
    }

    public List<User> getUser()
    {
        return userRepo.findAll();
    }
    public User findByUserName(String username)
    {
        return userRepo.findByUsername(username);
    }
}
