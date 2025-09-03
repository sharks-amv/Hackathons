package com.hospital.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Map;
import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/v1")
public class HealthController {

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        return ResponseEntity.ok(Map.of(
            "status", "UP",
            "timestamp", LocalDateTime.now(),
            "service", "Healthcare Backend API",
            "version", "1.0.0"
        ));
    }

    @GetMapping("/public/info")
    public ResponseEntity<Map<String, String>> publicInfo() {
        return ResponseEntity.ok(Map.of(
            "service", "Healthcare Management System",
            "version", "1.0.0",
            "description", "Secure healthcare management API"
        ));
    }
}