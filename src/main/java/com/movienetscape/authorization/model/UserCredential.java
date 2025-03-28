package com.movienetscape.authorization.model;


import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;


import java.time.LocalDateTime;
import java.util.*;


@Data
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "netscape_user_credential")
public class UserCredential {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long credentialId;

    @Column(nullable = false, unique = true)
    private String userId;

    @Column(nullable = false)
    private String passwordHash;



    @Column(nullable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private LocalDateTime updatedAt;


    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }


    public void changePassword(String newPassword) {
        this.passwordHash = newPassword;
        this.updatedAt = LocalDateTime.now();
    }

    public boolean validatePassword(String rawPassword, PasswordEncoder passwordEncoder) {
        return passwordEncoder.matches(rawPassword, this.passwordHash);
    }


    public void encryptCredentialPassword(String rawPassword, PasswordEncoder passwordEncoder) {
        this.passwordHash = passwordEncoder.encode(rawPassword);
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserCredential that = (UserCredential) o;
        return Objects.equals(credentialId, that.credentialId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(credentialId);
    }

    @Override
    public String toString() {
        return "Credential{" +
                "credentialId=" + credentialId +
                ", userId='" + userId + '\'' +
                ", createdAt=" + createdAt +
                ", updatedAt=" + updatedAt +
                '}';
    }




}
