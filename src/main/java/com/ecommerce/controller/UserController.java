package com.ecommerce.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class UserController {

    @GetMapping("/")
    public String greet(@AuthenticationPrincipal OAuth2User oauth2User) {
        String name = oauth2User.getAttribute("name");
        String email = oauth2User.getAttribute("email");
        java.util.Map<String, Object> attributes = oauth2User.getAttributes();

        return "Principal Name: " + name + "<br>" +
                "Principal Email: " + email + "<br>" +
                "Attributes: " + attributes;
    }

    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> me(OAuth2AuthenticationToken auth) {
        Map<String, Object> data = new HashMap<>();
        var attributes = auth.getPrincipal().getAttributes();
        data.put("email", attributes.get("email"));
        data.put("name", attributes.get("name"));

        return ResponseEntity.ok(data);
    }
}