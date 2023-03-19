package dev.crowell.authserverdemo.services;

import dev.crowell.authserverdemo.entities.ApiUser;
import dev.crowell.authserverdemo.repositories.ApiUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class ApiUserDetailsService implements UserDetailsService {
    private final ApiUserRepository repository;
    private final PasswordEncoder encoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        ApiUser user = repository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .roles("USER")
                .build();
    }

    public void registerUser(String username, String password) {
        ApiUser user = new ApiUser();
        user.setUsername(username);
        user.setPassword(encoder.encode(password));
        repository.save(user);
    }
}
