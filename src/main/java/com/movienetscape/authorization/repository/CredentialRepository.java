package com.movienetscape.authorization.repository;


import com.movienetscape.authorization.model.UserCredential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CredentialRepository extends JpaRepository<UserCredential, Long> {
    Optional<UserCredential> findByUserId(String userId);
}
