package com.healthcare.dto;

import java.time.LocalDate; // ⭐ IMPROVEMENT: Changed import
import java.time.LocalDateTime;

public class UserResponse {
    private Long id;
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private String phoneNumber;
    private LocalDate dateOfBirth; // ⭐ IMPROVEMENT: Changed type to LocalDate
    private String role;
    private Boolean isEnabled;
    private Boolean isAccountNonLocked;
    private LocalDateTime lastLogin;
    private LocalDateTime createdAt;

    // Constructors
    public UserResponse() {}

    public UserResponse(Long id, String username, String email, String firstName, String lastName, 
                       String role, Boolean isEnabled, LocalDateTime createdAt) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
        this.role = role;
        this.isEnabled = isEnabled;
        this.createdAt = createdAt;
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getFirstName() { return firstName; }
    public void setFirstName(String firstName) { this.firstName = firstName; }
    public String getLastName() { return lastName; }
    public void setLastName(String lastName) { this.lastName = lastName; }
    public String getPhoneNumber() { return phoneNumber; }
    public void setPhoneNumber(String phoneNumber) { this.phoneNumber = phoneNumber; }
    public LocalDate getDateOfBirth() { return dateOfBirth; } // ⭐ IMPROVEMENT: Updated getter/setter
    public void setDateOfBirth(LocalDate dateOfBirth) { this.dateOfBirth = dateOfBirth; }
    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
    public Boolean getIsEnabled() { return isEnabled; }
    public void setIsEnabled(Boolean enabled) { this.isEnabled = enabled; } // ✅ FIX: Used 'this' keyword
    public Boolean getIsAccountNonLocked() { return isAccountNonLocked; }
    public void setIsAccountNonLocked(Boolean accountNonLocked) { this.isAccountNonLocked = accountNonLocked; } // ✅ FIX: Used 'this' keyword
    public LocalDateTime getLastLogin() { return lastLogin; }
    public void setLastLogin(LocalDateTime lastLogin) { this.lastLogin = lastLogin; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    
    public String getFullName() {
        return firstName + " " + lastName;
    }
}