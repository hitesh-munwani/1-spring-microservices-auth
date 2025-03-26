package com.Loan.AuthService.jwtUtils;


import com.Loan.AuthService.Service.MyUserService;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private MyUserService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {

        final String authorizationHeader = request.getHeader("Authorization");
        String jwtToken = null;
        String username = null;

        // Check if the Authorization header contains a Bearer token
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwtToken = authorizationHeader.substring(7); // Extract token
            try {
                username = jwtUtil.extractUsername(jwtToken);
            } catch (ExpiredJwtException e) {
                logger.error("JWT Token Expired: " + e.getMessage());
            } catch (Exception e) {
                logger.error("JWT Token Error: " + e.getMessage());
            }
        }

        // Validate token and set authentication
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            if (jwtUtil.isTokenValid(jwtToken, userDetails.getUsername())) {
                UsernamePasswordAuthenticationFilter authToken = new UsernamePasswordAuthenticationFilter();
                authToken.setMessageSource((MessageSource) new WebAuthenticationDetailsSource().buildDetails(request));

                // Set authentication in the SecurityContext
                SecurityContextHolder.getContext().setAuthentication((Authentication) authToken);
            }
        }
        chain.doFilter(request, response);
    }

    // Extract & Validate JWT Token

}
