package com.crackit.SpringSecurityJWT.filter;

import com.crackit.SpringSecurityJWT.constant.AppConstants;
import com.crackit.SpringSecurityJWT.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        String authHeader = request.getHeader(AppConstants.HEADER_STRING);

        if (authHeader != null && authHeader.startsWith(AppConstants.TOKEN_PREFIX)) {
            String jwtToken = authHeader.substring(7);
            String userName = jwtService.extractUserName(jwtToken);

            if (userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails loadUserByUsername = userDetailsService.loadUserByUsername(userName);
                if (jwtService.isTokenValid(jwtToken, loadUserByUsername)) {
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                            loadUserByUsername,
                            null,
                            loadUserByUsername.getAuthorities()
                    );
                    authenticationToken.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request)
                    );
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }
            }
        }
        filterChain.doFilter(request, response);
    }
}
