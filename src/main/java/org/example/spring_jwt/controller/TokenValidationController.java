package org.example.spring_jwt.controller;

import lombok.AllArgsConstructor;
import org.example.spring_jwt.JWT.JWTUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@AllArgsConstructor
@Secured({"ROLE_USER", "ROLE_MODERATOR", "ROLE_SUPER_ADMIN", "ROLE_ANONYMOUS"})
public class TokenValidationController {

    private final JWTUtils jwtUtils;

    @GetMapping("/token/validate")
    public ResponseEntity<String> validateToken(@AuthenticationPrincipal UserDetails userDetails) {
        String username = userDetails.getUsername();
        boolean isValid = jwtUtils.isTokenValid(jwtUtils.generateToken(userDetails), userDetails);

        if (isValid) {
            return ResponseEntity.ok("Token is valid for user: " + username);
        } else {
            return ResponseEntity.status(401).body("Token is expired or invalid for user: " + username);
        }
    }
}
