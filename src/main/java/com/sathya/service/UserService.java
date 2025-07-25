package com.sathya.service;

import com.sathya.entity.User;
import com.sathya.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    // Change parameter from 'username' to 'email'
    public User registerUser(User user) {
        if (userRepository.findByEmail(user.getEmail()).isPresent()) { // Use findByEmail
            throw new RuntimeException("User already exists with email: " + user.getEmail()); // Update message
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        // Ensure role is stored as provided (e.g., "USER", "ADMIN")
        return userRepository.save(user);
    }

    // Change parameters from 'username' to 'email'
    public User validateUser(String email, String rawPassword) {
        return userRepository.findByEmail(email) // Use findByEmail
                .filter(user -> passwordEncoder.matches(rawPassword, user.getPassword()))
                .orElse(null);
    }

    // Change parameter from 'username' to 'email'
    public User getUserByEmail(String email) { // Renamed from getUserByUsername
        return userRepository.findByEmail(email) // Use findByEmail
                .orElseThrow(() -> new RuntimeException("User not found with email: " + email)); // Update message
    }

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }
}