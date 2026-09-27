package com.ioc.microservice.identityservice.controller;

import com.ioc.microservice.identityservice.dto.*;
import com.ioc.microservice.identityservice.entity.RefreshToken;
import com.ioc.microservice.identityservice.entity.User;
import com.ioc.microservice.identityservice.repository.UserRepository;
import com.ioc.microservice.identityservice.service.RefreshTokenService;
import com.ioc.microservice.identityservice.utils.JwtUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;
    private final JwtUtils jwtUtils;

    public AuthController(UserRepository userRepository,
                          RefreshTokenService refreshTokenService,
                          JwtUtils jwtUtils) {
        this.userRepository = userRepository;
        this.refreshTokenService = refreshTokenService;
        this.jwtUtils = jwtUtils;
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        User user = userRepository.findByUsername(loginRequest.getUsername())
                .orElseThrow(() -> new RuntimeException("Error: User not found!"));
        if (!user.getPassword().equals(loginRequest.getPassword())) {
            return ResponseEntity.badRequest().body("Error: Invalid password!");
        }
        String accessToken = jwtUtils.generateAccessToken(user.getUsername(), user.getRole());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());

        return ResponseEntity.ok(TokenResponseDTO.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken.getToken())
                .tokenType("Bearer")
                .build());
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponseDTO> refreshToken(@RequestBody RefreshTokenRequest request) {
        if (request.getRefreshToken() == null || request.getRefreshToken().isBlank()) {
            return ResponseEntity.badRequest().build();
        }

        TokenResponseDTO tokenResponse = refreshTokenService.refreshToken(request.getRefreshToken());
        return ResponseEntity.ok(tokenResponse);
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body("Error: Missing or invalid Authorization header!");
        }

        refreshTokenService.logout(authHeader);
        return ResponseEntity.ok("Logged out successfully!");
    }
}