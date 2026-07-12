package com.spring.security.models;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

@Data
@Document(collection = "verification_tokens")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VerificationToken {
    @Id
    private String id;

    @Indexed(unique = true)
    private String token;

    @DBRef
    private User user;

    @Indexed(expireAfterSeconds = 0)
    private Instant expiryDate;

    @Builder.Default
    private boolean used = false;
}