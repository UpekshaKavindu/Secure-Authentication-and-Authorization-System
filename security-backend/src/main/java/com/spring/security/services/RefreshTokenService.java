package com.spring.security.services;

import com.spring.security.models.RefreshToken;
import com.spring.security.models.User;
import com.spring.security.repo.RefreshTokenRepository;
import com.spring.security.utils.AppExceptions;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;
    @Value("${app.jwt.refresh-expiration-ms}")
    private long refreshExpirationMs;

    public RefreshToken createRefreshToken(User user) {
        // revoke all existing tokens for this user (rotation)
        refreshTokenRepository.deleteByUser_Id(user.getId());

        RefreshToken token = RefreshToken.builder()
                .token(UUID.randomUUID().toString())
                .user(user)
                .expiryDate(Instant.now().plusMillis(refreshExpirationMs))
                .revoked(false)
                .build();
        return refreshTokenRepository.save(token);
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Transactional
    public RefreshToken rotateRefreshToken(String oldTokenValue, User user) {
        // invalidate old one
        refreshTokenRepository.findByToken(oldTokenValue).ifPresent(token -> {
            token.setRevoked(true);
            refreshTokenRepository.save(token);
        });
        // create new
        return createRefreshToken(user);
    }

    public boolean isExpired(RefreshToken token) {
        return token.getExpiryDate().isBefore(Instant.now());
    }

    // Centralized validation — RuntimeException
    public RefreshToken validateToken(String tokenValue) {
        RefreshToken token = findByToken(tokenValue)
                .orElseThrow(() -> new AppExceptions.InvalidTokenException("Refresh token invalid"));

        if (token.isRevoked()) {
            throw new AppExceptions.InvalidTokenException("Refresh token revoked");
        }
        if (isExpired(token)) {
            throw new AppExceptions.InvalidTokenException("Refresh token expired");
        }
        return token;
    }
}
