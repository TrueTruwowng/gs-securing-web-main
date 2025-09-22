package com.example.securingweb;

import com.example.securingweb.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.CredentialsExpiredException;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {
    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Value("${security.login.show-username-errors:true}")
    private boolean showUsernameErrors;

    private static final Logger log = LoggerFactory.getLogger(WebSecurityConfig.class);

    private String digestHex(String algorithm, CharSequence raw) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] bytes = md.digest(raw.toString().getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            log.error("Digest algorithm {} not available", algorithm, e);
            return null;
        }
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder();
        return new PasswordEncoder() {
            @Override
            public String encode(CharSequence rawPassword) { return bcrypt.encode(rawPassword); }
            @Override
            public boolean matches(CharSequence rawPassword, String storedPassword) {
                if (storedPassword == null) return false;
                String trimmed = storedPassword.trim();
                boolean isBcrypt = trimmed.startsWith("$2a$") || trimmed.startsWith("$2b$") || trimmed.startsWith("$2y$");
                boolean is32Hex = trimmed.matches("[0-9a-fA-F]{32}"); // MD5
                boolean is64Hex = trimmed.matches("[0-9a-fA-F]{64}"); // SHA-256
                boolean result;
                String type;
                if (isBcrypt) {
                    type = "BCRYPT";
                    result = bcrypt.matches(rawPassword, trimmed);
                } else if (is32Hex) {
                    type = "MD5";
                    String md5 = digestHex("MD5", rawPassword);
                    result = md5 != null && md5.equalsIgnoreCase(trimmed);
                } else if (is64Hex) {
                    type = "SHA-256";
                    String sha = digestHex("SHA-256", rawPassword);
                    result = sha != null && sha.equalsIgnoreCase(trimmed);
                } else {
                    type = "PLAIN";
                    result = rawPassword.toString().equals(trimmed);
                }
                if (!result) {
                    log.warn("Password mismatch (storedType={}, storedLen={}, rawLen={})", type, trimmed.length(), rawPassword.length());
                } else {
                    log.debug("Password matched (storedType={})", type);
                }
                return result;
            }
        };
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        provider.setHideUserNotFoundExceptions(false);
        return provider;
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return (request, response, exception) -> {
            String username = request.getParameter("username");
            String code;
            if (exception instanceof UsernameNotFoundException) {
                code = showUsernameErrors ? "user" : "pwd"; // hide enumeration if disabled
            } else if (exception instanceof BadCredentialsException) {
                code = "pwd";
            } else if (exception instanceof LockedException) {
                code = "locked";
            } else if (exception instanceof DisabledException) {
                code = "disabled";
            } else if (exception instanceof AccountExpiredException) {
                code = "expired";
            } else if (exception instanceof CredentialsExpiredException) {
                code = "credexpired";
            } else {
                code = "other";
            }
            log.error("Authentication failed (code={}) for username='{}' : {}", code, username, exception.getMessage());
            String redirect = "/login?err=" + code;
            if (username != null && !username.isBlank()) {
                redirect += "&username=" + URLEncoder.encode(username, StandardCharsets.UTF_8);
            }
            response.sendRedirect(redirect);
        };
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authenticationProvider(authenticationProvider())
            .authorizeHttpRequests((requests) -> requests
                .requestMatchers("/", "/home", "/register", "/css/**", "/js/**", "/images/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/user").hasAnyRole("USER","ADMIN")
                .anyRequest().authenticated()
            )
            .formLogin((form) -> form
                .loginPage("/login")
                .failureHandler(authenticationFailureHandler())
                .successHandler((request, response, authentication) -> {
                    log.info("Authentication SUCCESS for user='{}'", authentication.getName());
                    // Role-based redirect
                    boolean isAdmin = authentication.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
                    String target = isAdmin ? "/admin" : "/user";
                    response.sendRedirect(target);
                })
                .permitAll()
            )
            .logout((logout) -> logout
                .addLogoutHandler((request, response, auth) -> {
                    if (auth != null) log.info("User '{}' logging out", auth.getName());
                })
                .logoutSuccessHandler((request, response, auth) -> {
                    log.info("Logout success");
                    response.sendRedirect("/login?logout");
                })
                .permitAll()
            );
        return http.build();
    }
}