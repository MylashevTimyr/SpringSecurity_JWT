package org.example.spring_jwt.controller;

import lombok.AllArgsConstructor;
import org.example.spring_jwt.model.User;
import org.example.spring_jwt.model.UserRole;
import org.example.spring_jwt.repository.UserRepository;
import org.example.spring_jwt.service.LoginAttemptService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/admin")
@AllArgsConstructor
public class AdminController {

    private final LoginAttemptService loginAttemptService;
    private final UserRepository userRepository;

    @PostMapping("/unlock/{username}")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<String> unlockAccount(@PathVariable String username) {
        loginAttemptService.resetAttempts(username);
        return ResponseEntity.ok("Account for user '" + username + "' unlocked successfully.");
    }

    @GetMapping("/status/{username}")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<String> getAccountStatus(@PathVariable String username) {
        Optional<User> user = userRepository.findByUsername(username);
        if (user.isPresent()) {
            return ResponseEntity.ok(
                    user.get().isAccountNonLocked() ? "User is not locked." : "User is locked."
            );
        } else {
            return ResponseEntity.badRequest().body("User not found.");
        }
    }
}