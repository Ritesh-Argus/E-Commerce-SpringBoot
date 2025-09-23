package com.ecommerce.model.entity;

import com.ecommerce.model.role.Role;
import jakarta.persistence.*;
import lombok.Data;

import java.util.Date;

@Entity
@Table(name = "users")
@Data
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String email;

    private String name;
    private String password;
    private String avatarUrl;

    @Enumerated(EnumType.STRING)
    private Role role = Role.CUSTOMER;
    private Date created_at = new Date();
    private Date updated_at = new Date();
}