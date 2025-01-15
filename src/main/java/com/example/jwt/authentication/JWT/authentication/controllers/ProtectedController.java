package com.example.jwt.authentication.JWT.authentication.controllers;

import com.example.jwt.authentication.JWT.authentication.dto.SessionDto;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@AllArgsConstructor
@RestController
@RequestMapping(value = "/protected")
public class ProtectedController {

    @ResponseStatus(HttpStatus.OK)
    @GetMapping(
            produces = MediaType.TEXT_PLAIN_VALUE
    )
    public ResponseEntity<String> getProtectedResource() {

        SessionDto session = (SessionDto) SecurityContextHolder
                .getContext()
                .getAuthentication()
                .getPrincipal();

        return ResponseEntity.ok(
                "Protected resource by " + session.getUserId().toString()
        );
    }
}
