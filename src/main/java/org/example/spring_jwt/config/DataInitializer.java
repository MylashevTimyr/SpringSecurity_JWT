package org.example.spring_jwt.config;

import lombok.AllArgsConstructor;
import org.example.spring_jwt.JWT.JWTUtils;
import org.example.spring_jwt.model.User;
import org.example.spring_jwt.model.UserRole;
import org.example.spring_jwt.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Collections;

@Component
@AllArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTUtils jwtUtils;

    @Override
    public void run(String... args) {
        if (userRepository.count() == 0) {
            User user = User.builder()
                    .username("user")
                    .password(passwordEncoder.encode("password"))
                    .role(UserRole.USER)
                    .accountNonLocked(true)
                    .build();

            User moderator = User.builder()
                    .username("moderator")
                    .password(passwordEncoder.encode("password"))
                    .role(UserRole.MODERATOR)
                    .accountNonLocked(true)
                    .build();

            User admin = User.builder()
                    .username("admin")
                    .password(passwordEncoder.encode("password"))
                    .role(UserRole.SUPER_ADMIN)
                    .accountNonLocked(true)
                    .build();

            userRepository.save(user);
            userRepository.save(moderator);
            userRepository.save(admin);

            System.out.println("Users created:");
            printUserTokens(user);
            printUserTokens(moderator);
            printUserTokens(admin);
        }
    }

    private void printUserTokens(User user) {
        String accessToken = jwtUtils.generateToken(
                new org.springframework.security.core.userdetails.User(
                        user.getUsername(),
                        user.getPassword(),
                        Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()))
                )
        );

        String refreshToken = jwtUtils.generateRefreshToken(
                new org.springframework.security.core.userdetails.User(
                        user.getUsername(),
                        user.getPassword(),
                        Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()))
                )
        );

        System.out.println("Username: " + user.getUsername());
        System.out.println("Access Token: " + accessToken);
        System.out.println("Refresh Token: " + refreshToken);
        System.out.println("----------------------------");
    }
}
