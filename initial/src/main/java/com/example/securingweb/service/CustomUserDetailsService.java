package com.example.securingweb.service;

import com.example.securingweb.model.User;
import com.example.securingweb.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.stream.Collectors;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;

    private static final Logger log = LoggerFactory.getLogger(CustomUserDetailsService.class);

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.debug("Attempting to load user: {}", username);
        User user = userRepository.findByUsername(username);
        if (user == null) {
            log.warn("User '{}' not found in database", username);
            throw new UsernameNotFoundException("User not found");
        }
        var roles = user.getRoles();
        if (roles == null || roles.isEmpty()) {
            log.warn("User '{}' has no roles assigned (continuing with empty authorities)", username);
        }
        var authorities = roles == null ? Collections.<SimpleGrantedAuthority>emptyList() : roles.stream()
            .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
            .collect(Collectors.toList());
        log.debug("Loaded user '{}' with roles {}", username, authorities);
        return new org.springframework.security.core.userdetails.User(
            user.getUsername(),
            user.getPassword(),
            authorities
        );
    }
}
