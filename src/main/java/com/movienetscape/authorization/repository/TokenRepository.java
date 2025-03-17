package com.movienetscape.authorization.repository;


import com.movienetscape.authorization.model.TokenVerification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TokenRepository extends JpaRepository<TokenVerification, Long> {
    TokenVerification findTokenVerificationByToken(String token);
}
