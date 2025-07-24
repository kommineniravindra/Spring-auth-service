package com.sathya.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Date;

public class JwtUtil {


    private static final String SECRET = "MySuperSecretKeyForJwtThatShouldBeLongEnough123456789ABCDEF"; // Increased length slightly
    private static final Key SECRET_KEY = Keys.hmacShaKeyFor(SECRET.getBytes());

 
    private static final long EXPIRATION_TIME = 60 * 60 * 1000;


    public static String generateToken(String username, String role, Long userId) {
        return Jwts.builder()
                .setSubject(username) 
                .claim("role", role) 
                .claim("userId", userId) 
                .setIssuedAt(new Date()) 
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME)) 
                .signWith(SECRET_KEY, SignatureAlgorithm.HS256) 
                .compact();
    }

    
    public static String extractUsername(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

   
    public static String extractRole(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return (String) claims.get("role"); // Retrieve the "role" claim
    }

    
    public static Long extractUserId(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.get("userId", Long.class); 
    }

   
    public static boolean validateToken(String token) {
        try {
            extractUsername(token); 
            return true;
        } catch (JwtException e) {
           
            System.err.println("JWT Validation failed: " + e.getMessage());
            return false;
        }
    }
}