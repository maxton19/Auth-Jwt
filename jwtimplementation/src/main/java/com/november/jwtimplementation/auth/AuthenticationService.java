package com.november.jwtimplementation.auth;

import com.november.jwtimplementation.config.JwtService;
import com.november.jwtimplementation.model.AppUser;
import com.november.jwtimplementation.model.Role;
import com.november.jwtimplementation.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    // Register a new user and generate a JWT token
    public AuthenticationResponse register(RegisterRequest registerRequest) {
        // Check if user already exists
        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            throw new IllegalStateException("Email already in use");
        }

        // Create and save the AppUser
        AppUser user = AppUser.builder()
                .firstName(registerRequest.getFirstName())
                .lastName(registerRequest.getLastName())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))  // Encoding the password
                .role(Role.USER)  // Default role is USER
                .build();
        userRepository.save(user);  // Save the user to the repository

        // Generate a JWT token for the new user
        String jwtToken = jwtService.generateToken(user);  // Ensure AppUser implements UserDetails or adapt as needed

        return AuthenticationResponse.builder()
                .token(jwtToken)  // Return the token in the response
                .build();
    }

    // Authenticate an existing user and generate a JWT token
    public AuthenticationResponse authenticate(AuthentificationRequest request) {
        try {
            // Perform authentication using AuthenticationManager
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );

            // Retrieve the authenticated user from the database
            AppUser user = userRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));

            // Generate a JWT token for the authenticated user
            String jwtToken = jwtService.generateToken(user);  // Ensure AppUser implements UserDetails

            return AuthenticationResponse.builder()
                    .token(jwtToken)  // Return the token in the response
                    .build();

        } catch (UsernameNotFoundException e) {
            throw new IllegalArgumentException("Invalid credentials: User not found");
        } catch (Exception e) {
            throw new IllegalStateException("Authentication failed: " + e.getMessage());
        }
    }
}
