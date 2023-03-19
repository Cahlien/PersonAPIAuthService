package dev.crowell.authserverdemo.models;

import lombok.Data;

@Data
public class RegistrationRequest {
    private String username;
    private String password;
}
