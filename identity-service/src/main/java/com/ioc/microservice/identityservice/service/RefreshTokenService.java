package com.ioc.microservice.identityservice.service;

import com.ioc.microservice.identityservice.dto.TokenResponseDTO;
import com.ioc.microservice.identityservice.entity.RefreshToken;
import com.ioc.microservice.identityservice.entity.User;
import com.ioc.microservice.identityservice.repository.RefreshTokenRepository;
import com.ioc.microservice.identityservice.repository.UserRepository;
import com.ioc.microservice.identityservice.utils.JwtUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
public class RefreshTokenService {

    @Value("${app.jwt.refresh-token-expiration}")
    private Long refreshTokenDurationMs;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtUtils jwtUtils;
    private final StringRedisTemplate redisTemplate;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository,
                               UserRepository userRepository,
                               JwtUtils jwtUtils,
                               StringRedisTemplate redisTemplate) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.jwtUtils = jwtUtils;
        this.redisTemplate = redisTemplate;
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Transactional
    public RefreshToken createRefreshToken(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + userId));

        refreshTokenRepository.deleteByUserId(userId);
        refreshTokenRepository.flush();

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));

        return refreshTokenRepository.save(refreshToken);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new RuntimeException("Refresh token was expired. Please make a new signin request");
        }
        return token;
    }

    @Transactional
    public int deleteByUserId(Long userId) {
        return refreshTokenRepository.deleteByUser(userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + userId)));
    }

    @Transactional
    public TokenResponseDTO refreshToken(String requestToken) {
        RefreshToken tokenInDb = refreshTokenRepository.findByToken(requestToken)
                .orElseThrow(() -> new RuntimeException("Refresh Token không tồn tại trong DB!"));

        verifyExpiration(tokenInDb);

        User user = tokenInDb.getUser();

        refreshTokenRepository.delete(tokenInDb);

        String newAccessToken = jwtUtils.generateAccessToken(user.getUsername(), user.getRole());
        RefreshToken newRefreshToken = createRefreshToken(user.getId());

        return TokenResponseDTO.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken.getToken())
                .tokenType("Bearer")
                .build();
    }

    @Transactional
    public void logout(String accessToken) {
        if (accessToken != null && accessToken.startsWith("Bearer ")) {
            accessToken = accessToken.substring(7);
        }

        String jti = jwtUtils.getJtiFromToken(accessToken);
        Date expiration = jwtUtils.getExpirationFromToken(accessToken);
        String username = jwtUtils.getUsernameFromToken(accessToken);

        long ttlInMillis = expiration.getTime() - System.currentTimeMillis();

        if (ttlInMillis > 0) {
            redisTemplate.opsForValue().set("blacklist:" + jti, "revoked", ttlInMillis, TimeUnit.MILLISECONDS);
        }

        userRepository.findByUsername(username).ifPresent(user -> {
            deleteByUserId(user.getId());
        });
    }

    public boolean isTokenBlacklisted(String jti) {
        Boolean hasKey = redisTemplate.hasKey("blacklist:" + jti);
        return Boolean.TRUE.equals(hasKey);
    }
}