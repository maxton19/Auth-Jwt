package com.november.jwtimplementation.auth;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthentificationRequest {

    private String username;
    private String password;

    public String getEmail() {
        return username;
    }
}
