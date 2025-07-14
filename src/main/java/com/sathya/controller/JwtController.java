package com.sathya.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.sathya.dto.LoginDetails;
import com.sathya.entity.User;
import com.sathya.service.UserService;
import com.sathya.util.JwtUtil;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class JwtController {

    private final UserService userService;

    // ✅ Signup Endpoint
    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody User user) {
        try {
            // 🔒 Allow only "Ravindra" to sign up as ADMIN
            if ("ADMIN".equalsIgnoreCase(user.getRole()) &&
                !"Ravindra".equalsIgnoreCase(user.getUsername())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body("❌ Only 'Ravindra' is allowed to register as ADMIN");
            }

            // 🟢 Allow all users to register as USER
            User savedUser = userService.registerUser(user);
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body("✅ Signup successful for user: " + savedUser.getUsername());
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body("❌ " + e.getMessage());
        }
    }

    // ✅ Login Endpoint
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginDetails loginDetails) {
        User user = userService.validateUser(loginDetails.getUsername(), loginDetails.getPassword());

        if (user != null) {
            // 🔒 Block any ADMIN login except Ravindra
            if ("ADMIN".equalsIgnoreCase(user.getRole()) &&
                !"Ravindra".equalsIgnoreCase(user.getUsername())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body("❌ Unauthorized ADMIN login attempt");
            }

            // ✅ Generate token and allow login
            String token = JwtUtil.generateToken(user.getUsername(), user.getRole(), user.getId());
            return ResponseEntity.ok(token);
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("❌ Invalid username or password");
        }
    }

    // ✅ Validate JWT and extract role
    @GetMapping("/validate")
    public ResponseEntity<String> validateToken(@RequestHeader("Authorization") String tokenHeader) {
        try {
            String token = tokenHeader.replace("Bearer ", "");
            String role = JwtUtil.extractRole(token);
            return ResponseEntity.ok(role);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Token");
        }
    }

    // ✅ Extract user ID from JWT
    @GetMapping("/user-id")
    public ResponseEntity<Long> extractUserId(@RequestHeader("Authorization") String tokenHeader) {
        try {
            String token = tokenHeader.replace("Bearer ", "");
            Long userId = JwtUtil.extractUserId(token);
            return ResponseEntity.ok(userId);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
}
