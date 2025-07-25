package com.sathya.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.SignatureAlgorithm; // Make sure this is imported

import java.security.Key;
import java.util.Date;

public class JwtUtil {

    private static final String SECRET = "MySuperSecretKeyForJwtThatShouldBeLongEnough123456789ABCDEF";
    private static final Key SECRET_KEY = Keys.hmacShaKeyFor(SECRET.getBytes());

    private static final long EXPIRATION_TIME = 60 * 60 * 1000; // 1 hour

    public static String generateToken(String email, String role, Long userId) {
        return Jwts.builder()
                .setSubject(email)
                .claim("role", role)
                .claim("userId", userId)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SECRET_KEY, SignatureAlgorithm.HS256) // SignatureAlgorithm needs to be imported
                .compact();
    }

    public static String extractEmail(String token) {
        return extractAllClaims(token).getSubject();
    }

    public static String extractRole(String token) {
        Claims claims = extractAllClaims(token);
        return (String) claims.get("role");
    }

    public static Long extractUserId(String token) {
        Claims claims = extractAllClaims(token);
        return claims.get("userId", Long.class);
    }

    private static Claims extractAllClaims(String token) {
        String cleanedToken = token.startsWith("Bearer ") ? token.substring(7) : token;
        return Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(cleanedToken)
                .getBody();
    }

    public static boolean validateToken(String token) {
        try {
            extractEmail(token);
            return true;
        } catch (io.jsonwebtoken.JwtException e) {
            System.err.println("JWT Validation failed: " + e.getMessage());
            return false;
        }
    }
}