package com.example.jwt.authentication.JWT.authentication.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;

@Getter
public class AuthenticationRequestDto {

    @JsonProperty("email_address")
    private String emailAddress;

    @JsonProperty("password")
    private String password;
}
