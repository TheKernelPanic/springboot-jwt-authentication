package com.example.jwt.authentication.JWT.authentication.services;

import com.example.jwt.authentication.JWT.authentication.dto.TokenDto;
import com.example.jwt.authentication.JWT.authentication.utils.JwtUtil;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

@AllArgsConstructor
@Service
public class AuthenticationService {

    private final JwtUtil jwtUtil;

    public TokenDto execute(String emailAddress, String password) {

        // TODO: Check user credentials

        UUID userId = UUID.randomUUID();

        return new TokenDto(
                this.jwtUtil.generateToken(
                        userId
                )
        );
    }
}
