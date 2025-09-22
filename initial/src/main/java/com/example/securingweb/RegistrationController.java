package com.example.securingweb;

import com.example.securingweb.service.UserRegistrationService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class RegistrationController {

    private final UserRegistrationService registrationService;

    public RegistrationController(UserRegistrationService registrationService) {
        this.registrationService = registrationService;
    }

    @GetMapping("/register")
    public String showRegister(@RequestParam(value = "username", required = false) String username,
                               @RequestParam(value = "error", required = false) String error,
                               Model model) {
        model.addAttribute("prefillUsername", username);
        model.addAttribute("errorMessage", error);
        return "register";
    }

    @PostMapping("/register")
    public String handleRegister(@RequestParam("username") String username,
                                 @RequestParam("password") String password,
                                 @RequestParam("confirmPassword") String confirmPassword,
                                 RedirectAttributes ra) {
        if (!password.equals(confirmPassword)) {
            ra.addAttribute("username", username);
            ra.addAttribute("error", "Mật khẩu xác nhận không khớp");
            return "redirect:/register";
        }
        try {
            registrationService.registerNewUser(username, password);
        } catch (IllegalArgumentException ex) {
            ra.addAttribute("username", username);
            ra.addAttribute("error", ex.getMessage());
            return "redirect:/register";
        }
        // redirect to login with success flag and pre-filled username
        ra.addAttribute("reg", "ok");
        ra.addAttribute("username", username);
        return "redirect:/login";
    }
}

