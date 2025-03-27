package com.Loan.AuthService.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserService implements UserDetailsService {

    @Autowired
    private UserService userService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        com.Loan.AuthService.model.User byUserName = userService.findByUserName(username);
        if (byUserName == null) {
            throw new UsernameNotFoundException("User not found");
        }
        return User.builder()
                .username(byUserName.getUsername())
                .password(byUserName.getPassword())
                .authorities("ROLE_USER") // Default role
                .build();
    }
}