package com.example.jwt.authentication.JWT.authentication.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;

@AllArgsConstructor
public class TokenDto {

    @JsonProperty("token")
    private String token;
}
