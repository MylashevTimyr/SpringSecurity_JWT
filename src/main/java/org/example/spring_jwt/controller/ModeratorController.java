package org.example.spring_jwt.controller;

import lombok.RequiredArgsConstructor;
import org.example.spring_jwt.model.User;
import org.example.spring_jwt.repository.UserRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/moderator")
@RequiredArgsConstructor
public class ModeratorController {

    private final UserRepository userRepository;

    @PreAuthorize("hasRole('MODERATOR')")
    @PostMapping("/content")
    public ResponseEntity<String> moderateContent() {
        return ResponseEntity.ok("Content moderated successfully");
    }

    @GetMapping("/user-status/{username}")
    @PreAuthorize("hasRole('MODERATOR')")
    public ResponseEntity<String> checkUserLockStatus(@PathVariable String username) {
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
