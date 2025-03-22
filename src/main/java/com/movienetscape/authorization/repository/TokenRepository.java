package com.movienetscape.authorization.repository;


import com.movienetscape.authorization.model.TokenVerification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface TokenRepository extends JpaRepository<TokenVerification, Long> {
    TokenVerification findTokenVerificationByToken(String token);

    TokenVerification findTokenVerificationByUserId(String userId);
}
