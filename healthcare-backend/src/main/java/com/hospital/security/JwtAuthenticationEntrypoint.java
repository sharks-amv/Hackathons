package com.hospital.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hospital.service.AuditService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * JWT Authentication Entry Point
 * Handles unauthorized access attempts and security violations
 * Implements A07: Identification and Authentication Failures protection
 */
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationEntryPoint.class);
    
    private final AuditService auditService;
    private final ObjectMapper objectMapper;

    public JwtAuthenticationEntryPoint(AuditService auditService) {
        this.auditService = auditService;
        this.objectMapper = new ObjectMapper();
        this.objectMapper.findAndRegisterModules(); // For LocalDateTime serialization
    }

    @Override
    public void commence(HttpServletRequest request, 
                        HttpServletResponse response, 
                        AuthenticationException authException) throws IOException, ServletException {
        
        String requestURI = request.getRequestURI();
        String method = request.getMethod();
        String clientIp = getClientIp(request);
        String userAgent = request.getHeader("User-Agent");

        logger.warn("Unauthorized access attempt: {} {} from {} - {}", 
                   method, requestURI, clientIp, authException.getMessage());

        // Log security event for monitoring
        auditService.logSecurityEvent(
            "anonymous", 
            "UNAUTHORIZED_ACCESS_ATTEMPT", 
            clientIp,
            String.format("Unauthorized %s request to %s: %s", method, requestURI, authException.getMessage())
        );

        // Check for potential attack patterns
        detectSuspiciousActivity(request, authException);

        // Set security headers
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Expires", "0");

        // Create structured error response
        Map<String, Object> errorResponse = createErrorResponse(request, authException);

        // Write JSON response
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
        response.getWriter().flush();
    }

    /**
     * Create structured error response
     */
    private Map<String, Object> createErrorResponse(HttpServletRequest request, AuthenticationException authException) {
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("timestamp", LocalDateTime.now());
        errorResponse.put("status", HttpServletResponse.SC_UNAUTHORIZED);
        errorResponse.put("error", "Unauthorized");
        errorResponse.put("message", determineErrorMessage(authException));
        errorResponse.put("path", request.getRequestURI());
        errorResponse.put("method", request.getMethod());
        
        // Don't expose sensitive information in production
        if (isDebugMode()) {
            errorResponse.put("details", authException.getMessage());
        }
        
        return errorResponse;
    }

    /**
     * Determine appropriate error message based on exception type
     */
    private String determineErrorMessage(AuthenticationException authException) {
        String exceptionName = authException.getClass().getSimpleName();
        
        return switch (exceptionName) {
            case "BadCredentialsException" -> "Invalid credentials provided";
            case "AccountExpiredException" -> "Account has expired";
            case "CredentialsExpiredException" -> "Credentials have expired";
            case "DisabledException" -> "Account is disabled";
            case "LockedException" -> "Account is locked";
            case "UsernameNotFoundException" -> "Authentication required";
            default -> "Full authentication is required to access this resource";
        };
    }

    /**
     * Detect suspicious activity patterns
     */
    private void detectSuspiciousActivity(HttpServletRequest request, AuthenticationException authException) {
        String clientIp = getClientIp(request);
        String userAgent = request.getHeader("User-Agent");
        String requestURI = request.getRequestURI();

        // Check for common attack patterns
        if (containsSuspiciousPatterns(requestURI)) {
            auditService.logSecurityEvent(
                "anonymous", 
                "SUSPICIOUS_REQUEST_PATTERN", 
                clientIp,
                "Suspicious URI pattern detected: " + requestURI
            );
        }

        // Check for missing or suspicious User-Agent
        if (userAgent == null || userAgent.trim().isEmpty() || containsSuspiciousUserAgent(userAgent)) {
            auditService.logSecurityEvent(
                "anonymous", 
                "SUSPICIOUS_USER_AGENT", 
                clientIp,
                "Suspicious or missing User-Agent: " + userAgent
            );
        }

        // Log repeated unauthorized attempts (implement rate limiting logic here)
        // This would typically check against a cache/database for repeated attempts
    }

    /**
     * Check for suspicious URI patterns
     */
    private boolean containsSuspiciousPatterns(String uri) {
        String[] suspiciousPatterns = {
            "../", "..\\", "..", 
            "script", "javascript", "vbscript",
            "union", "select", "insert", "update", "delete",
            "cmd", "exec", "eval",
            "wp-admin", "phpMyAdmin", ".php", ".asp", ".jsp"
        };
        
        String lowerUri = uri.toLowerCase();
        for (String pattern : suspiciousPatterns) {
            if (lowerUri.contains(pattern.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check for suspicious User-Agent strings
     */
    private boolean containsSuspiciousUserAgent(String userAgent) {
        if (userAgent == null) return true;
        
        String[] suspiciousAgents = {
            "sqlmap", "nikto", "burp", "nmap", "masscan",
            "bot", "crawler", "spider", "scraper",
            "curl", "wget", "python-requests"
        };
        
        String lowerAgent = userAgent.toLowerCase();
        for (String suspicious : suspiciousAgents) {
            if (lowerAgent.contains(suspicious)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get client IP address with proxy support
     */
    private String getClientIp(HttpServletRequest request) {
        // Check X-Forwarded-For header (most common)
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (isValidIp(xForwardedFor)) {
            return xForwardedFor.split(",")[0].trim();
        }

        // Check X-Real-IP header
        String xRealIp = request.getHeader("X-Real-IP");
        if (isValidIp(xRealIp)) {
            return xRealIp.trim();
        }

        // Check X-Original-Forwarded-For header
        String xOriginalForwardedFor = request.getHeader("X-Original-Forwarded-For");
        if (isValidIp(xOriginalForwardedFor)) {
            return xOriginalForwardedFor.split(",")[0].trim();
        }

        // Fallback to remote address
        return request.getRemoteAddr();
    }

    /**
     * Validate IP address
     */
    private boolean isValidIp(String ip) {
        return ip != null && !ip.trim().isEmpty() && !ip.equalsIgnoreCase("unknown");
    }

    /**
     * Check if application is in debug mode
     */
    private boolean isDebugMode() {
        // This should check your application properties
        // For now, return false for security
        return false;
    }
}