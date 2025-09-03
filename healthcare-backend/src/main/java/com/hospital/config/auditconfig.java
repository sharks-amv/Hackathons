package com.hospital.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;
import java.util.concurrent.Executor;

/**
 * Audit Configuration
 * Implements A09: Security Logging and Monitoring Failures protection
 * Configures JPA auditing and async processing for audit logs
 */
@Configuration
@EnableJpaAuditing(auditorAwareRef = "auditorProvider")
@EnableAsync
public class AuditConfig {

    /**
     * Auditor provider to track who made changes
     */
    @Bean
    public AuditorAware<String> auditorProvider() {
        return new SpringSecurityAuditorAware();
    }

    /**
     * Async executor for audit logging to prevent blocking main operations
     */
    @Bean(name = "auditExecutor")
    public Executor auditExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(5);
        executor.setMaxPoolSize(10);
        executor.setQueueCapacity(500);
        executor.setThreadNamePrefix("audit-");
        executor.setRejectedExecutionHandler(new ThreadPoolTaskExecutor.CallerRunsPolicy());
        executor.initialize();
        return executor;
    }

    /**
     * Async executor for security event processing
     */
    @Bean(name = "securityEventExecutor")
    public Executor securityEventExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(3);
        executor.setMaxPoolSize(8);
        executor.setQueueCapacity(200);
        executor.setThreadNamePrefix("security-");
        executor.setRejectedExecutionHandler(new ThreadPoolTaskExecutor.CallerRunsPolicy());
        executor.initialize();
        return executor;
    }

    /**
     * Custom auditor aware implementation
     */
    public static class SpringSecurityAuditorAware implements AuditorAware<String> {

        @Override
        public Optional<String> getCurrentAuditor() {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication == null || !authentication.isAuthenticated()) {
                return Optional.of("system");
            }

            Object principal = authentication.getPrincipal();

            if (principal instanceof UserDetails) {
                return Optional.of(((UserDetails) principal).getUsername());
            } else if (principal instanceof String) {
                return Optional.of((String) principal);
            } else if ("anonymousUser".equals(principal)) {
                return Optional.of("anonymous");
            }

            return Optional.of("system");
        }
    }
}

/**
 * Audit Event Configuration for custom audit events
 */
@Configuration
public class AuditEventConfig {

    /**
     * Custom audit event types
     */
    public enum AuditEventType {
        USER_LOGIN("User logged in"),
        USER_LOGOUT("User logged out"),
        USER_REGISTRATION("User registered"),
        PASSWORD_CHANGE("Password changed"),
        ACCOUNT_LOCKED("Account locked"),
        ACCOUNT_UNLOCKED("Account unlocked"),
        PERMISSION_DENIED("Permission denied"),
        DATA_ACCESS("Data accessed"),
        DATA_EXPORT("Data exported"),
        CONFIGURATION_CHANGE("Configuration changed"),
        SYSTEM_ERROR("System error occurred");

        private final String description;

        AuditEventType(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }

    /**
     * Security event severity levels
     */
    public enum SecuritySeverity {
        LOW("Low priority security event"),
        MEDIUM("Medium priority security event"),
        HIGH("High priority security event"),
        CRITICAL("Critical security event requiring immediate attention");

        private final String description;

        SecuritySeverity(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }
}

/**
 * Audit Service Configuration for cleanup and monitoring
 */
@Configuration
public class AuditServiceConfig {

    /**
     * Scheduled task configuration for audit log cleanup
     */
    @Bean
    public AuditCleanupTask auditCleanupTask() {
        return new AuditCleanupTask();
    }

    /**
     * Configuration for audit retention policy
     */
    @Bean
    public AuditRetentionPolicy auditRetentionPolicy() {
        return new AuditRetentionPolicy();
    }

    /**
     * Audit cleanup task implementation
     */
    public static class AuditCleanupTask {
        
        private int auditLogRetentionDays = 365;
        private int securityEventRetentionDays = 2555; // 7 years for compliance
        private boolean cleanupEnabled = true;

        public int getAuditLogRetentionDays() { return auditLogRetentionDays; }
        public void setAuditLogRetentionDays(int auditLogRetentionDays) { this.auditLogRetentionDays = auditLogRetentionDays; }

        public int getSecurityEventRetentionDays() { return securityEventRetentionDays; }
        public void setSecurityEventRetentionDays(int securityEventRetentionDays) { this.securityEventRetentionDays = securityEventRetentionDays; }

        public boolean isCleanupEnabled() { return cleanupEnabled; }
        public void setCleanupEnabled(boolean cleanupEnabled) { this.cleanupEnabled = cleanupEnabled; }
    }

    /**
     * Audit retention policy implementation
     */
    public static class AuditRetentionPolicy {
        
        private boolean compressOldLogs = true;
        private boolean archiveBeforeDelete = true;
        private String archivePath = "/var/log/healthcare/archive";
        private int compressionThresholdDays = 90;

        public boolean isCompressOldLogs() { return compressOldLogs; }
        public void setCompressOldLogs(boolean compressOldLogs) { this.compressOldLogs = compressOldLogs; }

        public boolean isArchiveBeforeDelete() { return archiveBeforeDelete; }
        public void setArchiveBeforeDelete(boolean archiveBeforeDelete) { this.archiveBeforeDelete = archiveBeforeDelete; }

        public String getArchivePath() { return archivePath; }
        public void setArchivePath(String archivePath) { this.archivePath = archivePath; }

        public int getCompressionThresholdDays() { return compressionThresholdDays; }
        public void setCompressionThresholdDays(int compressionThresholdDays) { this.compressionThresholdDays = compressionThresholdDays; }
    }
}

/**
 * Audit interceptor configuration for automatic audit logging
 */
@Configuration
public class AuditInterceptorConfig {

    /**
     * Method interceptor for automatic audit logging of service methods
     */
    @Bean
    public AuditMethodInterceptor auditMethodInterceptor() {
        return new AuditMethodInterceptor();
    }

    /**
     * Custom audit method interceptor
     */
    public static class AuditMethodInterceptor {
        
        private boolean enabled = true;
        private String[] includedPackages = {"com.hospital.service", "com.hospital.controller"};
        private String[] excludedMethods = {"toString", "equals", "hashCode", "getClass"};

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }

        public String[] getIncludedPackages() { return includedPackages; }
        public void setIncludedPackages(String[] includedPackages) { this.includedPackages = includedPackages; }

        public String[] getExcludedMethods() { return excludedMethods; }
        public void setExcludedMethods(String[] excludedMethods) { this.excludedMethods = excludedMethods; }
    }
}