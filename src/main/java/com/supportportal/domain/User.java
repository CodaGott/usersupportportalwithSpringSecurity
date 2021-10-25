package com.supportportal.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class User implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(nullable = false, updatable = false)
    private Long id;
    private String userId;
    private String firstName;
    private String lastName;
    private String username;
    private String password;
    private String email;
    private String phoneNumber;
    private String profileImageUrl;
    private Date lastLoginDate;
    private Date lastLoginDayDisplay;
    private Date joinedDate;
    private String [] roles; // ROLE_USER, ROLE_ADMIN
    private String [] authorities;
    private Boolean isActive;
    private Boolean isNotLocked;
}
