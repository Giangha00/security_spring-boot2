package com.sem4.security_springboot2.repository;

import com.sem4.security_springboot2.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    boolean existsByUsername(String username);

    @Query("SELECT u.tokenVersion FROM User u WHERE u.username = :username")
    Optional<Integer> findTokenVersionByUsername(@Param("username") String username);

    @Query("SELECT u.enabled FROM User u WHERE u.username = :username")
    Optional<Boolean> findEnabledByUsername(@Param("username") String username);
}
