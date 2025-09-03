package com.hospital.controller;

import com.hospital.dto.*;
import com.hospital.entity.User;
import com.hospital.entity.UserRole;
import com.hospital.service.UserService;
import com.hospital.service.AuditService;
import com.hospital.security.InputSanitizer;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * User Management Controller
 * Implements secure user operations with proper authorization checks
 * Protects against A01: Broken Access Control and A03: Injection
 */
@RestController
@RequestMapping("/api/v1/users")
@CrossOrigin(origins = {"https://localhost:3000", "https://localhost:3001"})
@Validated
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    private final UserService userService;
    private final AuditService auditService;
    private final InputSanitizer inputSanitizer;

    public UserController(UserService userService,
                         AuditService auditService,
                         InputSanitizer inputSanitizer) {
        this.userService = userService;
        this.auditService = auditService;
        this.inputSanitizer = inputSanitizer;
    }

    /**
     * Get current user's profile
     */
    @GetMapping("/profile")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UserResponse> getCurrentUserProfile(HttpServletRequest request) {
        String currentUsername = getCurrentUsername();
        
        auditService.logUserAction(currentUsername, "PROFILE_VIEW", "User", null,
                Map.of("action", "view_own_profile", "ip", getClientIp(request)));

        User user = userService.findByUsername(currentUsername);
        UserResponse response = convertToUserResponse(user);
        
        logger.info("User {} viewed their profile", currentUsername);
        return ResponseEntity.ok(response);
    }

    /**
     * Update current user's profile
     */
    @PutMapping("/profile")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UserResponse> updateCurrentUserProfile(
            @Valid @RequestBody UpdateProfileRequest request,
            HttpServletRequest httpRequest) {
        
        String currentUsername = getCurrentUsername();
        
        // Sanitize input
        sanitizeProfileRequest(request);
        
        User user = userService.findByUsername(currentUsername);
        UserResponse updatedUser = userService.updateUserProfile(user.getId(), request, currentUsername);
        
        auditService.logUserAction(currentUsername, "PROFILE_UPDATE", "User", 
                user.getId().toString(), Map.of(
                    "updatedFields", getUpdatedFields(request),
                    "ip", getClientIp(httpRequest)
                ));

        logger.info("User {} updated their profile", currentUsername);
        return ResponseEntity.ok(updatedUser);
    }

    /**
     * Get user by ID (Admin/Doctor only)
     */
    @GetMapping("/{userId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('DOCTOR')")
    public ResponseEntity<UserResponse> getUserById(@PathVariable Long userId,
                                                   HttpServletRequest request) {
        String currentUsername = getCurrentUsername();
        
        Optional<User> userOpt = userService.findById(userId);
        if (userOpt.isEmpty()) {
            auditService.logSecurityEvent(currentUsername, "USER_NOT_FOUND_ACCESS", 
                    getClientIp(request), "Attempted to access non-existent user: " + userId);
            return ResponseEntity.notFound().build();
        }

        User user = userOpt.get();
        
        // Additional authorization: doctors can only view patients
        if (hasRole("DOCTOR") && !hasRole("ADMIN")) {
            if (user.getRole() != UserRole.PATIENT) {
                auditService.logSecurityEvent(currentUsername, "UNAUTHORIZED_USER_ACCESS", 
                        getClientIp(request), "Doctor attempted to access non-patient user: " + userId);
                return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            }
        }

        auditService.logDataAccess(currentUsername, "User", userId.toString(), "READ");
        
        UserResponse response = convertToUserResponse(user);
        logger.info("User {} accessed user profile: {}", currentUsername, userId);
        
        return ResponseEntity.ok(response);
    }

    /**
     * Get all users (Admin only)
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<UserResponse>> getAllUsers(
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "20") @Min(1) int size,
            @RequestParam(required = false) String role,
            @RequestParam(required = false) String search,
            HttpServletRequest request) {

        String currentUsername = getCurrentUsername();

        // Sanitize search input
        if (search != null) {
            search = inputSanitizer.sanitizeText(search);
            if (inputSanitizer.containsSqlInjection(search) || 
                inputSanitizer.containsXss(search)) {
                auditService.logSecurityEvent(currentUsername, "MALICIOUS_SEARCH_ATTEMPT", 
                        getClientIp(request), "Malicious search query detected: " + search);
                return ResponseEntity.badRequest().build();
            }
        }

        Page<UserResponse> users;
        if (search != null && !search.trim().isEmpty()) {
            users = userService.searchUsers(search, page, size);
        } else if (role != null) {
            try {
                UserRole userRole = UserRole.valueOf(role.toUpperCase());
                List<UserResponse> roleUsers = userService.getUsersByRole(userRole);
                // Convert to Page (simplified implementation)
                users = createPage(roleUsers, page, size);
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest().build();
            }
        } else {
            List<UserResponse> allUsers = userService.getAllUsers();
            users = createPage(allUsers, page, size);
        }

        auditService.logUserAction(currentUsername, "USER_LIST_VIEW", "User", null,
                Map.of("page", page, "size", size, "search", search != null ? search : "null",
                       "role", role != null ? role : "null", "ip", getClientIp(request)));

        logger.info("Admin {} viewed user list (page: {}, size: {})", currentUsername, page, size);
        return ResponseEntity.ok(users);
    }

    /**
     * Update user by ID (Admin only)
     */
    @PutMapping("/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserResponse> updateUser(@PathVariable Long userId,
                                                  @Valid @RequestBody AdminUpdateUserRequest request,
                                                  HttpServletRequest httpRequest) {
        String currentUsername = getCurrentUsername();

        Optional<User> userOpt = userService.findById(userId);
        if (userOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        // Sanitize input
        sanitizeAdminUpdateRequest(request);

        UserResponse updatedUser = userService.adminUpdateUser(userId, request, currentUsername);

        auditService.logUserAction(currentUsername, "USER_ADMIN_UPDATE", "User", 
                userId.toString(), Map.of(
                    "updatedFields", getAdminUpdatedFields(request),
                    "targetUser", updatedUser.getUsername(),
                    "ip", getClientIp(httpRequest)
                ));

        logger.info("Admin {} updated user {}", currentUsername, updatedUser.getUsername());
        return ResponseEntity.ok(updatedUser);
    }

    /**
     * Delete user (Admin only)
     */
    @DeleteMapping("/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> deleteUser(@PathVariable Long userId,
                                                          HttpServletRequest request) {
        String currentUsername = getCurrentUsername();

        Optional<User> userOpt = userService.findById(userId);
        if (userOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        User userToDelete = userOpt.get();
        String usernameToDelete = userToDelete.getUsername();

        // Prevent admin from deleting themselves
        if (userToDelete.getUsername().equals(currentUsername)) {
            auditService.logSecurityEvent(currentUsername, "SELF_DELETE_ATTEMPT", 
                    getClientIp(request), "Admin attempted to delete their own account");
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Cannot delete your own account"));
        }

        userService.deleteUser(userId, currentUsername);

        auditService.logUserAction(currentUsername, "USER_DELETE", "User", 
                userId.toString(), Map.of(
                    "deletedUser", usernameToDelete,
                    "ip", getClientIp(request)
                ));

        logger.warn("Admin {} deleted user {}", currentUsername, usernameToDelete);
        return ResponseEntity.ok(Map.of("message", "User deleted successfully"));
    }

    /**
     * Enable/Disable user account (Admin only)
     */
    @PatchMapping("/{userId}/status")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> updateUserStatus(
            @PathVariable Long userId,
            @RequestBody UserStatusRequest request,
            HttpServletRequest httpRequest) {

        String currentUsername = getCurrentUsername();

        Optional<User> userOpt = userService.findById(userId);
        if (userOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        User user = userOpt.get();
        String action = request.isEnabled() ? "ENABLE" : "DISABLE";

        userService.updateUserStatus(userId, request.isEnabled(), currentUsername);

        auditService.logUserAction(currentUsername, "USER_STATUS_UPDATE", "User", 
                userId.toString(), Map.of(
                    "action", action,
                    "targetUser", user.getUsername(),
                    "newStatus", request.isEnabled(),
                    "ip", getClientIp(httpRequest)
                ));

        String message = String.format("User %s %s successfully", 
                user.getUsername(), request.isEnabled() ? "enabled" : "disabled");

        logger.info("Admin {} {} user {}", currentUsername, 
                request.isEnabled() ? "enabled" : "disabled", user.getUsername());

        return ResponseEntity.ok(Map.of("message", message));
    }

    /**
     * Reset user password (Admin only)
     */
    @PostMapping("/{userId}/reset-password")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> resetUserPassword(
            @PathVariable Long userId,
            @Valid @RequestBody ResetPasswordRequest request,
            HttpServletRequest httpRequest) {

        String currentUsername = getCurrentUsername();

        Optional<User> userOpt = userService.findById(userId);
        if (userOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        User user = userOpt.get();

        userService.adminResetPassword(userId, request.getNewPassword(), currentUsername);

        auditService.logUserAction(currentUsername, "PASSWORD_ADMIN_RESET", "User", 
                userId.toString(), Map.of(
                    "targetUser", user.getUsername(),
                    "ip", getClientIp(httpRequest)
                ));

        logger.warn("Admin {} reset password for user {}", currentUsername, user.getUsername());
        return ResponseEntity.ok(Map.of("message", "Password reset successfully"));
    }

    /**
     * Change current user's password
     */
    @PostMapping("/change-password")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, String>> changePassword(
            @Valid @RequestBody ChangePasswordRequest request,
            HttpServletRequest httpRequest) {

        String currentUsername = getCurrentUsername();

        boolean success = userService.changePassword(currentUsername, 
                request.getCurrentPassword(), request.getNewPassword());

        if (success) {
            auditService.logPasswordChange(currentUsername, getClientIp(httpRequest), true);
            logger.info("User {} changed their password", currentUsername);
            return ResponseEntity.ok(Map.of("message", "Password changed successfully"));
        } else {
            auditService.logPasswordChange(currentUsername, getClientIp(httpRequest), false);
            logger.warn("Failed password change attempt for user {}", currentUsername);
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Current password is incorrect"));
        }
    }

    /**
     * Get user statistics (Admin only)
     */
    @GetMapping("/statistics")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getUserStatistics(HttpServletRequest request) {
        String currentUsername = getCurrentUsername();

        Map<String, Object> statistics = userService.getUserStatistics();

        auditService.logUserAction(currentUsername, "USER_STATISTICS_VIEW", "User", null,
                Map.of("ip", getClientIp(request)));

        logger.info("Admin {} viewed user statistics", currentUsername);
        return ResponseEntity.ok(statistics);
    }

    /**
     * Get users with expired passwords (Admin only)
     */
    @GetMapping("/expired-passwords")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserResponse>> getUsersWithExpiredPasswords(HttpServletRequest request) {
        String currentUsername = getCurrentUsername();

        List<UserResponse> expiredUsers = userService.getUsersWithExpiredPasswords();

        auditService.logUserAction(currentUsername, "EXPIRED_PASSWORDS_VIEW", "User", null,
                Map.of("count", expiredUsers.size(), "ip", getClientIp(request)));

        logger.info("Admin {} viewed users with expired passwords ({})", 
                currentUsername, expiredUsers.size());

        return ResponseEntity.ok(expiredUsers);
    }

    // Helper methods

    /**
     * Get current authenticated username
     */
    private String getCurrentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof UserDetails) {
            return ((UserDetails) authentication.getPrincipal()).getUsername();