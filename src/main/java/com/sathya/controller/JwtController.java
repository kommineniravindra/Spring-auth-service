package com.sathya.controller;

import com.sathya.dto.LoginDetails;
import com.sathya.entity.User;
import com.sathya.service.UserService;
import com.sathya.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class JwtController {

    private final UserService userService;

    // ✅ Signup: Any user can register (ADMIN or USER)
    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody User user) {
        try {
            User savedUser = userService.registerUser(user);
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body("✅ Signup successful for user: " + savedUser.getUsername());
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body("❌ " + e.getMessage());
        }
    }

    // ✅ Login: Allow all users (ADMIN or USER)
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginDetails loginDetails) {
        User user = userService.validateUser(loginDetails.getUsername(), loginDetails.getPassword());

        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("❌ Invalid username or password");
        }

        String token = JwtUtil.generateToken(user.getUsername(), user.getRole(), user.getId());
        return ResponseEntity.ok(token);
    }

    // ✅ Validate token and return user role
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

    // ✅ Extract user ID from token
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
