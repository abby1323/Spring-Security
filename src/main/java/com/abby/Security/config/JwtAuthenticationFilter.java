package com.abby.Security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
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

    private JWTService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {

                //1. check if we have JWT token
                final String authHeader = request.getHeader("Authorisation");
                final String jwt;
                final String userEmail;
                // if token not present
                if(authHeader==null || authHeader.startsWith("Bearer ")){
                    filterChain.doFilter(request,response);
                    return;
                }

                //extract token from header
                jwt = authHeader.substring(7);
                //extract user email
                userEmail = jwtService.extractUserName(jwt);
                // call UserDetails Service to check if User already present in Database
                if(userEmail!=null && SecurityContextHolder
                        .getContext().getAuthentication() == null){
                    //fetch user from DB
                    UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

                    if(jwtService.isTokenValid(jwt, userDetails)){
                        //token is valid
                        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                        );
                        authToken.setDetails(
                                new WebAuthenticationDetailsSource()
                                        .buildDetails(request)
                        );

                        //update Security Context Holder

                        SecurityContextHolder.getContext().setAuthentication(authToken);
                    }
                }
                //hand over to next filter
                filterChain.doFilter(request,response);

    }
}
