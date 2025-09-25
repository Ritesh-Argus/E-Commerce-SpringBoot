package com.ecommerce.service;

import com.ecommerce.model.entity.User;
import com.ecommerce.model.role.Role;
import com.ecommerce.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public User findOrCreateGoogleUser(String email, String name, Role role) {
        return userRepository.findByEmail(email).orElseGet(() -> {
            User newUser = new User();
            newUser.setEmail(email);
            newUser.setName(name);
            newUser.setRole(role);
            return userRepository.save(newUser);
        });
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }
}