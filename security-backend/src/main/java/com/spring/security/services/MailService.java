package com.spring.security.services;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MailService {
    private static final Logger logger = LoggerFactory.getLogger(MailService.class);

    @Autowired
    private JavaMailSender mailSender;

    @Value("${app.mail.from}")
    private String fromAddress;

    @Value("${app.frontend.base-url:http://localhost:5173}")
    private String frontendBaseUrl;

    public void sendVerificationEmail(String toEmail, String firstName, String token) {
        String verificationLink = frontendBaseUrl + "/verify-email?token=" + token;

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromAddress);
        message.setTo(toEmail);
        message.setSubject("Verify your Travel Booking account");
        message.setText(
                "Hi " + firstName + ",\n\n" +
                        "Thanks for registering. Please verify your email address by clicking the link below:\n\n" +
                        verificationLink + "\n\n" +
                        "This link expires in 24 hours. If you didn't create this account, you can ignore this email.\n\n" +
                        "— Travel Booking Team"
        );

        try {
            mailSender.send(message);
            logger.info("Verification email sent to {}", toEmail);
        } catch (MailException e) {
            logger.error("Failed to send verification email to {}: {}", toEmail, e.getMessage());
            throw e;
        }
    }
}