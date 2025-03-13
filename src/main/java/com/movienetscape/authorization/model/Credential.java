package com.movienetscape.authorization.model;


import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;


import java.time.LocalDateTime;
import java.util.Objects;



@Data
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "netscape_user_credential")
public class Credential {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long credentialId;

    @Column(nullable = false, unique = true)
    private String userId;

    @Column(nullable = false)
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private LocalDateTime updatedAt;

    public Credential(String userId, Role role) {
        this.userId = userId;
        this.role = role;
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }


    public void updatePasswordHash(String newPasswordHash) {
        this.passwordHash = newPasswordHash;
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
        Credential that = (Credential) o;
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
                ", role=" + role +
                ", createdAt=" + createdAt +
                ", updatedAt=" + updatedAt +
                '}';
    }


}
