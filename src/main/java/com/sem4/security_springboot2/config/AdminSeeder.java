package com.sem4.security_springboot2.config;

import com.sem4.security_springboot2.entity.Role;
import com.sem4.security_springboot2.entity.User;
import com.sem4.security_springboot2.repository.RoleRepository;
import com.sem4.security_springboot2.repository.UserRepository;
import com.sem4.security_springboot2.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@ConditionalOnProperty(name = "app.seed-admin.enabled", havingValue = "true")
public class AdminSeeder implements ApplicationRunner {
    private static final Logger log = LoggerFactory.getLogger(AdminSeeder.class);

    private final UserRepository users;
    private final RoleRepository roles;
    private final PasswordEncoder passwordEncoder;
    private final String username;
    private final String password;

    public AdminSeeder(UserRepository users,
                       RoleRepository roles,
                       PasswordEncoder passwordEncoder,
                       @Value("${app.seed-admin.username}") String username,
                       @Value("${app.seed-admin.password}") String password) {
        this.users = users;
        this.roles = roles;
        this.passwordEncoder = passwordEncoder;
        this.username = UserService.normalize(username);
        this.password = password;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        Role roleUser = roles.findByName(Role.ROLE_USER).orElseGet(() -> roles.save(new Role(Role.ROLE_USER)));
        Role roleAdmin = roles.findByName(Role.ROLE_ADMIN).orElseGet(() -> roles.save(new Role(Role.ROLE_ADMIN)));

        if (!users.existsByUsername(username)) {
            User admin = new User(username, passwordEncoder.encode(password));
            admin.getRoles().add(roleUser);
            admin.getRoles().add(roleAdmin);
            users.save(admin);
            log.info("Đã tạo tài khoản ADMIN '{}'", username);
        }

        String normalUser = "user";
        if (!users.existsByUsername(normalUser)) {
            User standardUser = new User(normalUser, passwordEncoder.encode("User#Catalog2026"));
            standardUser.getRoles().add(roleUser);
            users.save(standardUser);
            log.info("Đã tạo tài khoản USER thường '{}'", normalUser);
        }
    }
}
