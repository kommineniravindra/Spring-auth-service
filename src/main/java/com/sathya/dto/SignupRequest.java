package com.sathya.dto;

import lombok.Data;

@Data
public class SignupRequest {
    private String email; // Changed from username to email
    private String password;
    private String role;
}