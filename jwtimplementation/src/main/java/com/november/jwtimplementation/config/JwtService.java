package com.november.jwtimplementation.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "QYepys8uIMxVNz8ifFJFotOhG55jW2E8";  // Your secret key

    // Extract the username (subject) from the token
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // Generic method to extract claims from the token
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Generate a JWT token based on claims and UserDetails
    public String generateToken(Map<String, Object> claims, UserDetails userDetails) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())  // Set the subject (username)
                .setIssuedAt(new Date(System.currentTimeMillis()))  // Set the issue date
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))  // Set the expiration date (10 hours)
                .signWith(getSigningKey())  // Sign the token with the secret key
                .compact();
    }

    // Default token generation method without additional claims
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    // Validate the JWT token by checking if it is expired and matches the user
    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    // Check if the token has expired
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // Extract the expiration date from the token
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // Extract all claims from the JWT token
    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parser()
                    .setSigningKey(getSigningKey())  // Set the signing key for validation
                    .build()
                    .parseClaimsJws(token)  // Parse the JWT token
                    .getBody();
        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            throw new com.november.jwtimplementation.exception.JwtTokenException("JWT token is expired", e);
        } catch (io.jsonwebtoken.MalformedJwtException e) {
            throw new com.november.jwtimplementation.exception.JwtTokenException("JWT token is malformed", e);
        } catch (io.jsonwebtoken.SignatureException e) {
            throw new com.november.jwtimplementation.exception.JwtTokenException("JWT signature validation failed", e);
        } catch (Exception e) {
            throw new com.november.jwtimplementation.exception.JwtTokenException("Invalid JWT token", e);
        }
    }

    // Get the signing key (secret key) for JWT token signing and validation
    private Key getSigningKey() {
        try {
            // If the secret key is already in plain text, we don't need Base64 decoding
            return Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
        } catch (IllegalArgumentException e) {
            throw new com.november.jwtimplementation.exception.JwtTokenException("Invalid Secret Key", e);
        }
    }
}
