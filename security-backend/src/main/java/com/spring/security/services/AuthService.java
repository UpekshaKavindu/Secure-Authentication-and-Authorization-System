package com.spring.security.services;

import com.mongodb.DuplicateKeyException;
import com.spring.security.dto.AuthResponse;
import com.spring.security.dto.LoginRequest;
import com.spring.security.dto.RegisterRequest;
import com.spring.security.models.RefreshToken;
import com.spring.security.models.Role;
import com.spring.security.models.User;
import com.spring.security.models.VerificationToken;
import com.spring.security.repo.RefreshTokenRepository;
import com.spring.security.repo.UserRepository;
import com.spring.security.utils.AppExceptions;
import com.spring.security.utils.CookieUtil;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final CookieUtil cookieUtil;
    private final MailService mailService;
    private final EmailVerificationService emailVerificationService;
    private static final Logger logger =
            LoggerFactory.getLogger(AuthService.class);

    @Value("${app.jwt.access-expiration-ms}")
    private long accessExpMs;
    @Value("${app.jwt.refresh-expiration-ms}")
    private long refreshExpMs;
    @Value("${app.security.max-failed-attempts:5}")
    private int maxFailedAttempts;

    @Value("${app.security.lock-duration-minutes:15}")
    private int lockDurationMinutes;

    @Value("${app.security.require-email-verification}")
    private boolean requireEmailVerification;

    @Transactional
    public void register(@Valid RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new AppExceptions.EmailAlreadyExistsException("Email already registered");
        }
        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .role(Role.CUSTOMER)
                .enabled(!requireEmailVerification)  // For simplicity; email verification later
                .build();
        try{
            userRepository.save(user);
        }catch(DuplicateKeyException ex){
            throw new AppExceptions.EmailAlreadyExistsException("Email already exists");
        }
    }

    private void sendVerificationEmail(User user) {
        VerificationToken token = emailVerificationService.createVerificationToken(user);
        try {
            mailService.sendVerificationEmail(user.getEmail(), user.getFirstName(), token.getToken());
        } catch (MailException e) {
            logger.error("Could not send verification email to {} — user can retry via resend endpoint", user.getEmail());
        }
    }

    @Transactional
    public void resendVerification(String email) {
        userRepository.findByEmail(email).ifPresent(user -> {
            if (!user.isEnabled()) {
                sendVerificationEmail(user);
            }
        });
    }

    @Transactional
    public void verifyEmail(String token) {
        User user = emailVerificationService.validateAndConsume(token);
        user.setEnabled(true);
        userRepository.save(user);
        logger.info("Email verified for user {}", user.getEmail());
    }

    @Transactional
    public AuthResponse login(@Valid LoginRequest request, HttpServletResponse response) {
        User existingUser = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new AppExceptions.UserNotFoundException("Invalid credentials"));


        // Lock time expired checking — auto-unlock
        if (!existingUser.isAccountNonLocked() && existingUser.getLockTime() != null) {
            if (existingUser.getLockTime().plusMinutes(lockDurationMinutes).isBefore(LocalDateTime.now())) {
                existingUser.setAccountNonLocked(true);
                existingUser.setFailedLoginAttempts(0);
                existingUser.setLockTime(null);
                userRepository.save(existingUser);
            } else {
                logger.info(existingUser.getEmail() + " is locked");
                throw new AppExceptions.AccountLockedException(
                        "Account locked. Please try again after " + lockDurationMinutes + " minutes."
                );
            }
        }

        try {
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
            );


            User user = (User) auth.getPrincipal();

            // Successful login → failed attempts reset
            if (user.getFailedLoginAttempts() > 0) {
                user.setFailedLoginAttempts(0);
                user.setAccountNonLocked(true);
                user.setLockTime(null);
                userRepository.save(user);
            }

            // Create tokens
            String accessToken = jwtService.generateAccessToken(user.getEmail());
            String refreshTokenStr = jwtService.generateRefreshToken(user.getEmail());  // JWT-based refresh token
            RefreshToken refreshTokenEntity = refreshTokenService.createRefreshToken(user);


            // Set cookies
            int accessMaxAge = (int) (accessExpMs / 1000);
            int refreshMaxAge = (int) (refreshExpMs / 1000);
            cookieUtil.createAccessTokenCookie(response, accessToken, accessMaxAge);
            cookieUtil.createRefreshTokenCookie(response, refreshTokenEntity.getToken(), refreshMaxAge);
            logger.info("User {} logged in", user.getEmail());

            return new AuthResponse(user.getEmail(), user.getRole().name());
        }catch (BadCredentialsException e) {
            // FIX #4: Wrong password — attempt count
            handleFailedLogin(existingUser);
            throw e;
        }
    }

    // Failed attempt logic
    private void handleFailedLogin(User user) {
        int attempts = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(attempts);

        if (attempts >= maxFailedAttempts) {
            user.setAccountNonLocked(false);
            user.setLockTime(LocalDateTime.now());
        }
        userRepository.save(user);
    }

    @Transactional
    public AuthResponse refresh(String refreshTokenValue, HttpServletResponse response) {
        RefreshToken refreshToken = refreshTokenService.validateToken(refreshTokenValue);
        User user = refreshToken.getUser();
        RefreshToken newRefreshToken = refreshTokenService.rotateRefreshToken(refreshTokenValue, user);
        String newAccessToken = jwtService.generateAccessToken(user.getEmail());

        int accessMaxAge = (int)(accessExpMs / 1000);
        int refreshMaxAge = (int)(refreshExpMs / 1000);
        cookieUtil.createAccessTokenCookie(response, newAccessToken, accessMaxAge);
        cookieUtil.createRefreshTokenCookie(response, newRefreshToken.getToken(), refreshMaxAge);

        return new AuthResponse(user.getEmail(), user.getRole().name());
    }

    public void logout(String refreshTokenValue,HttpServletResponse response) {
        if (refreshTokenValue != null) {
            refreshTokenService.findByToken(refreshTokenValue).ifPresent(token -> {
                token.setRevoked(true);
                refreshTokenRepository.save(token);
            });
        }
        logger.info("User logged out successfully");
        cookieUtil.clearCookies(response);
    }
}
