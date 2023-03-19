package dev.crowell.authserverdemo.controllers;

import dev.crowell.authserverdemo.models.RegistrationRequest;
import dev.crowell.authserverdemo.services.ApiUserDetailsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api/v1/registration")
@Slf4j
@RequiredArgsConstructor
public class RegistrationController {
    private final ApiUserDetailsService service;

    @PostMapping
    public ResponseEntity<Void> registerUser(@RequestBody RegistrationRequest request) {
        log.info("Registering user {} with password {}", request.getUsername(), request.getPassword());
        service.registerUser(request.getUsername(), request.getPassword());
        return new ResponseEntity<>(HttpStatus.CREATED);
    }
}
