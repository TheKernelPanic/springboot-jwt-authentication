package com.example.jwt.authentication.JWT.authentication.controllers;

import com.example.jwt.authentication.JWT.authentication.dto.AuthenticationRequestDto;
import com.example.jwt.authentication.JWT.authentication.dto.TokenDto;
import com.example.jwt.authentication.JWT.authentication.services.AuthenticationService;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@AllArgsConstructor
@RestController
@RequestMapping(value = "/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @ResponseStatus(HttpStatus.OK)
    @GetMapping(
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<TokenDto> authenticate(
            @RequestBody AuthenticationRequestDto request
    ) {
        return ResponseEntity.ok(
                this.authenticationService
                        .execute(
                                request.getEmailAddress(),
                                request.getPassword()
                        )
        );
    }
}
