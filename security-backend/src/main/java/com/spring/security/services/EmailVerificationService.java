package com.spring.security.services;

import com.spring.security.models.User;
import com.spring.security.models.VerificationToken;
import com.spring.security.repo.VerificationTokenRepository;
import com.spring.security.utils.AppExceptions;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class EmailVerificationService {
    private final VerificationTokenRepository verificationTokenRepository;

    @Value("${app.security.verification-token-expiration-ms:86400000}")
    private long verificationExpirationMs;

    @Transactional
    public VerificationToken createVerificationToken(User user) {
        verificationTokenRepository.deleteByUser_Id(user.getId());

        VerificationToken token = VerificationToken.builder()
                .token(UUID.randomUUID().toString())
                .user(user)
                .expiryDate(Instant.now().plusMillis(verificationExpirationMs))
                .used(false)
                .build();
        return verificationTokenRepository.save(token);
    }

    @Transactional
    public User validateAndConsume(String tokenValue) {
        VerificationToken token = verificationTokenRepository.findByToken(tokenValue)
                .orElseThrow(() -> new AppExceptions.InvalidTokenException("Verification link is invalid"));

        if (token.isUsed()) {
            throw new AppExceptions.InvalidTokenException("Verification link has already been used");
        }
        if (token.getExpiryDate().isBefore(Instant.now())) {
            throw new AppExceptions.InvalidTokenException("Verification link has expired");
        }

        token.setUsed(true);
        verificationTokenRepository.save(token);

        return token.getUser();
    }
}