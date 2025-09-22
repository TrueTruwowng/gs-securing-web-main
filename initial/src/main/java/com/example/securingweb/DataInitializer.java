package com.example.securingweb;

import com.example.securingweb.model.Role;
import com.example.securingweb.model.User;
import com.example.securingweb.repository.RoleRepository;
import com.example.securingweb.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import java.util.Set;

@Configuration
@ConditionalOnProperty(name = "app.data.initialize", havingValue = "true", matchIfMissing = true)
public class DataInitializer {
    @Bean
    CommandLineRunner initData(UserRepository userRepo, RoleRepository roleRepo, PasswordEncoder encoder) {
        return args -> {
            // Seed roles if missing
            Role userRole = roleRepo.findByName("USER");
            if (userRole == null) {
                userRole = new Role();
                userRole.setName("USER");
                userRole = roleRepo.save(userRole);
            }
            Role adminRole = roleRepo.findByName("ADMIN");
            if (adminRole == null) {
                adminRole = new Role();
                adminRole.setName("ADMIN");
                adminRole = roleRepo.save(adminRole);
            }
            // Only create default accounts if they don't already exist
            if (userRepo.findByUsername("user") == null) {
                User user = new User();
                user.setUsername("user");
                user.setPassword(encoder.encode("password"));
                user.setRoles(Set.of(userRole));
                userRepo.save(user);
            }
            if (userRepo.findByUsername("admin") == null) {
                User admin = new User();
                admin.setUsername("admin");
                admin.setPassword(encoder.encode("adminpass"));
                admin.setRoles(Set.of(adminRole));
                userRepo.save(admin);
            }
        };
    }
}
