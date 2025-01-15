package com.example.jwt.authentication.JWT.authentication.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.UUID;

@AllArgsConstructor
@Getter
public class SessionDto {
    private UUID userId;
}
