package com.sem4.security_springboot2.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class WebController {

    @Value("${server.port:8088}")
    private String serverPort;

    @Value("${app.jwt.active-kid:key-1}")
    private String activeKid;

    @Value("${app.seed-admin.username:admin}")
    private String defaultAdminUser;

    @GetMapping({"/", "/catalog"})
    public String index(Model model) {
        model.addAttribute("serverPort", serverPort);
        model.addAttribute("activeKid", activeKid);
        model.addAttribute("defaultAdminUser", defaultAdminUser);
        return "index";
    }

    @GetMapping("/login")
    public String login(Model model) {
        model.addAttribute("serverPort", serverPort);
        model.addAttribute("defaultAdminUser", defaultAdminUser);
        return "index";
    }
}
