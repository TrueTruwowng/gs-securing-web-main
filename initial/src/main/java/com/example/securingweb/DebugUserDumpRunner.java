package com.example.securingweb;

import com.example.securingweb.model.User;
import com.example.securingweb.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class DebugUserDumpRunner {

    private static final Logger log = LoggerFactory.getLogger(DebugUserDumpRunner.class);

    @Value("${app.debug.dump-users:false}")
    private boolean dumpUsers;

    @Bean
    CommandLineRunner dumpUsers(UserRepository userRepository) {
        return args -> {
            if (!dumpUsers) return;
            log.warn("[DEBUG] Dumping users (passwords masked) because app.debug.dump-users=true");
            for (User u : userRepository.findAll()) {
                String pw = u.getPassword();
                String type;
                if (pw == null) type = "NULL";
                else if (pw.startsWith("$2a$") || pw.startsWith("$2b$") || pw.startsWith("$2y$")) type = "BCRYPT";
                else if (pw.matches("[0-9a-fA-F]{32}")) type = "MD5";
                else if (pw.matches("[0-9a-fA-F]{64}")) type = "SHA-256";
                else type = "PLAIN";
                String masked = pw == null ? "null" : (pw.length() <= 8 ? "********" : pw.substring(0,6) + "...(" + pw.length()+")");
                String roles = (u.getRoles()==null||u.getRoles().isEmpty())?"<no roles>":u.getRoles().stream().map(r->r.getName()).reduce((a,b)->a+","+b).orElse("");
                log.warn("[DEBUG] User id={} username='{}' pwType={} pwMasked={} roles={}", u.getId(), u.getUsername(), type, masked, roles);
            }
        };
    }
}

