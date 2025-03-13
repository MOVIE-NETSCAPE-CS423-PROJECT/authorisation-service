package com.movienetscape.authorization.repository;


import com.movienetscape.authorization.model.Credential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CredentialRepository extends JpaRepository<Credential, Long> {
    Optional<Credential> findByUserId(String userId);
}
