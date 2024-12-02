package org.example.spring_jwt.service;

import lombok.AllArgsConstructor;
import org.example.spring_jwt.model.User;
import org.example.spring_jwt.repository.UserRepository;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@AllArgsConstructor
public class LoginAttemptService {

    private final UserRepository userRepository;

    private static final int MAX_ATTEMPTS = 5;

    @Transactional
    public void loginFailed(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        int attempts = user.getFailedAttempts() + 1;
        user.setFailedAttempts(attempts);

        if (attempts >= MAX_ATTEMPTS) {
            user.setAccountNonLocked(false);
        }

        userRepository.save(user);
    }

    @Transactional
    public void loginSucceeded(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        user.setFailedAttempts(0);
        user.setAccountNonLocked(true);
        userRepository.save(user);
    }

    @Transactional
    public void resetAttempts(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        user.setFailedAttempts(0);
        user.setAccountNonLocked(true);
        userRepository.save(user);
    }
}
