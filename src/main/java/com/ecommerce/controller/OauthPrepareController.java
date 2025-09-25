package com.ecommerce.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
@RequestMapping("/")
public class OauthPrepareController {

    @GetMapping("/auth/prepare")
    public void prepareOauth(HttpServletRequest request,
                             HttpServletResponse response,
                             @RequestParam(name = "role", required = false) String role) throws IOException {

        HttpSession session = request.getSession(true);

        if (role != null && !role.isBlank()) {
            if (role.equals("SELLER")) {
                session.setAttribute("oauth_role", role);
            } else {
                session.setAttribute("oauth_role", "CUSTOMER");
            }
        } else {
            session.setAttribute("oauth_role", "CUSTOMER");
        }
        response.sendRedirect("/oauth2/authorization/google");
    }
}
