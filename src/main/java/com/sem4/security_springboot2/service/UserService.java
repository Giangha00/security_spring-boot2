package com.sem4.security_springboot2.service;

import com.sem4.security_springboot2.entity.User;
import com.sem4.security_springboot2.exception.ResourceNotFoundException;
import com.sem4.security_springboot2.repository.UserRepository;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public static String normalize(String username) {
        return username == null ? "" : username.trim().toLowerCase();
    }

    @Transactional(readOnly = true)
    public User getByUsername(String username) {
        return userRepository.findByUsername(normalize(username))
            .orElseThrow(() -> new ResourceNotFoundException("User not found: " + username));
    }

    @Transactional
    public void changePassword(String username, String currentPassword, String newPassword) {
        User user = getByUsername(username);

        if (!passwordEncoder.matches(currentPassword, user.getPasswordHash())) {
            throw new BadCredentialsException("Mật khẩu hiện tại không chính xác");
        }

        user.setPasswordHash(passwordEncoder.encode(newPassword));
        user.setTokenVersion(user.getTokenVersion() + 1);
        userRepository.save(user);
    }

    @Transactional
    public void incrementTokenVersion(String username) {
        User user = getByUsername(username);
        user.setTokenVersion(user.getTokenVersion() + 1);
        userRepository.save(user);
    }

    @Transactional
    public void lockUser(String username) {
        User user = getByUsername(username);
        user.setEnabled(false);
        user.setTokenVersion(user.getTokenVersion() + 1);
        userRepository.save(user);
    }
}
