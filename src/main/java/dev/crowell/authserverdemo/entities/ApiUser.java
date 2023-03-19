package dev.crowell.authserverdemo.entities;

import jakarta.persistence.*;
import lombok.Data;
import lombok.RequiredArgsConstructor;


@Entity
@Table(name = "api_users")
@Data
@RequiredArgsConstructor
public class ApiUser {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false, unique = true)
    private String username;
    @Column(nullable = false)
    private String password;
}
