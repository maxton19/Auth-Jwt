package com.november.jwtimplementation.repository;

import com.november.jwtimplementation.model.AppUser;  // Correct import for your AppUser model
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<AppUser, Integer> {  // Use AppUser instead of User

    Optional<AppUser> findByEmail(String email);  // Correct the return type to AppUser

    boolean existsByEmail(String email);
}
