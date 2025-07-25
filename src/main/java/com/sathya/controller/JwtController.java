package com.sathya.controller;

import com.sathya.dto.LoginDetails;
import com.sathya.dto.SignupRequest;
import com.sathya.dto.AuthResponse;
import com.sathya.entity.User;
import com.sathya.service.UserService;
import com.sathya.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class JwtController {

    private final UserService userService;

    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody SignupRequest signupRequest) {
        try {
            User newUser = new User();
            newUser.setEmail(signupRequest.getEmail()); // Use email
            newUser.setPassword(signupRequest.getPassword());
            newUser.setRole(signupRequest.getRole());

            User savedUser = userService.registerUser(newUser);
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body("✅ Signup successful for user: " + savedUser.getEmail()); // Display email
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body("❌ " + e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginDetails loginDetails) {
        // Use email for validation
        User user = userService.validateUser(loginDetails.getEmail(), loginDetails.getPassword());

        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                   .body(new AuthResponse(null, null, "Invalid email or password", null)); // Changed message, added email field in AuthResponse if desired
        }

        // Generate token using user's email
        String token = JwtUtil.generateToken(user.getEmail(), user.getRole(), user.getId());

        // Return AuthResponse with email
        return ResponseEntity.ok(new AuthResponse(token, user.getRole(), user.getEmail(), user.getEmail())); // Pass email here
    }

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

    @GetMapping("/user-email") // NEW: Endpoint to get user email from token
    public ResponseEntity<String> extractUserEmail(@RequestHeader("Authorization") String tokenHeader) {
        try {
            String token = tokenHeader.replace("Bearer ", "");
            String email = JwtUtil.extractEmail(token); // Assuming you add extractEmail to JwtUtil
            return ResponseEntity.ok(email);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Token or Email not found");
        }
    }

    @GetMapping("/users/all")
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = userService.getAllUsers();
        return ResponseEntity.ok(users);
    }
}