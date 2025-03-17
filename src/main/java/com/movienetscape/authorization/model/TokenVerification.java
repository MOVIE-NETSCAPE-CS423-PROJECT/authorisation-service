package com.movienetscape.authorization.model;

import com.movienetscape.usermanagementservice.model.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;


@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenVerification {

    @Id
    @Column(unique = true)
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(unique = true)
    private String token;

    @Column(nullable = false)
    private LocalDateTime tokenExpirationTime;


    @Column(nullable = false)
    private boolean verified;

    @Column(nullable = false)
    private String userId;
}
