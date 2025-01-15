package com.example.jwt.authentication.JWT.authentication.filters;


import com.example.jwt.authentication.JWT.authentication.dto.SessionDto;
import com.example.jwt.authentication.JWT.authentication.exceptions.InvalidTokenException;
import com.example.jwt.authentication.JWT.authentication.utils.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    private final HandlerExceptionResolver handlerExceptionResolver;

    private final JwtUtil jwtUtil;

    @Autowired
    public JwtRequestFilter(
            HandlerExceptionResolver handlerExceptionResolver,
            JwtUtil jwtUtil
    ) {
        this.handlerExceptionResolver = handlerExceptionResolver;
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        final String requestTokenHeader = request.getHeader("Authorization");

        if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {

            String jwtToken = requestTokenHeader.substring(7);

            try {

                if (!this.jwtUtil.validateToken(jwtToken)) {
                    throw new InvalidTokenException(
                           "Jwt is expired"
                    );
                }
                SessionDto session = new SessionDto(
                        this.jwtUtil.getUserId(jwtToken)
                );
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        session,
                        null,
                        null
                );
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);

            } catch (InvalidTokenException exception) {
                this.handlerExceptionResolver.resolveException(request, response, null, exception);
            }
        }
        filterChain.doFilter(request, response);
    }
}
