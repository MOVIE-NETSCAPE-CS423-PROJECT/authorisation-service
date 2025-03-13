package com.movienetscape.authorization.service;

import com.movienetscape.authorization.dto.request.CreateCredentialResponse;
import com.movienetscape.authorization.dto.response.LoginResponse;
import com.movienetscape.authorization.dto.response.RefreshTokenResponse;
import com.movienetscape.authorization.util.exception.LoginException;
import com.movienetscape.authorization.model.Credential;
import com.movienetscape.authorization.model.Role;
import com.movienetscape.authorization.repository.CredentialRepository;
import com.movienetscape.authorization.util.exception.InternalServerErrorException;
import com.movienetscape.authorization.util.exception.TokenExpiredException;
import com.movienetscape.authorization.util.TokenGrant;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Service
@Transactional
public class AuthorisationService {

    private final CredentialRepository credentialRepository;
    private final PasswordEncoder passwordEncoder;
    private final RSAKey rsaKey;
    private final TokenStoreService tokenStore;

    public AuthorisationService(CredentialRepository credentialRepository, PasswordEncoder passwordEncoder, RSAKey rsaKey, TokenStoreService tokenStore) {
        this.credentialRepository = credentialRepository;
        this.passwordEncoder = passwordEncoder;
        this.rsaKey = rsaKey;
        this.tokenStore = tokenStore;
    }

    public LoginResponse validateCredential(String userId, String password) {

        return credentialRepository.findByUserId(userId)
                .map(credential -> {
                    if (credential.validatePassword(password, passwordEncoder)) {
                        var accessToken = generateAccessToken(userId, credential.getRole());
                        String refreshToken = generateRefreshToken(userId);

                        return new LoginResponse(
                                "Logged in successfully",
                                userId,
                                accessToken.token(),
                                refreshToken,
                                accessToken.expiresIn()
                        );
                    } else {
                        throw new LoginException("Invalid Credential");
                    }
                })
                .orElseThrow(() -> new LoginException("Invalid Credential"));
    }

    public RefreshTokenResponse refreshToken(String refreshToken) {
        String userId = tokenStore.getUserIdByRefreshToken(refreshToken);

        if (userId == null) {
            throw new TokenExpiredException("Invalid RefreshToken. Please log in again.");
        }

        Credential credential = credentialRepository.findByUserId(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Get the old access token from Redis
        String oldAccessToken = extractOldAccessTokenFromRedis(userId);
        if (oldAccessToken != null) {
            try {
                SignedJWT signedJWT = SignedJWT.parse(oldAccessToken);
                String jti = signedJWT.getJWTClaimsSet().getJWTID();
                if (jti != null) {
                    // Blacklist the old access token using JTI and expiration time
                    long expirationTimeInSeconds = getRemainingExpirationTime(oldAccessToken);
                    tokenStore.blacklistAccessToken(jti, expirationTimeInSeconds);
                }
            } catch (Exception e) {
                throw new RuntimeException("Failed to parse old access token", e);
            }
        }

        // Generate new tokens
        var newAccessTokenGrant = generateAccessToken(userId, credential.getRole());
        var newResourceToken = generateRefreshToken(userId);

        // Remove the old refresh token from the token store
        tokenStore.removeRefreshToken(refreshToken);

        // Return the new tokens
        return new RefreshTokenResponse(
                newAccessTokenGrant.token(),
                newResourceToken,
                newAccessTokenGrant.expiresIn()
        );
    }


    private String generateRefreshToken(String userId) {
        String refreshToken = UUID.randomUUID().toString();
        tokenStore.storeRefreshToken(refreshToken, userId);
        return refreshToken;
    }


    private String extractOldAccessTokenFromRedis(String userId) {
        return tokenStore.getAccessTokenForUser(userId);
    }

    public void logout(String accessToken, String refreshToken) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(accessToken);
            String jti = signedJWT.getJWTClaimsSet().getJWTID();
            long expirationTimeInSeconds = getRemainingExpirationTime(accessToken);

            if (jti != null) {
                // Blacklist the access token by its JTI and expiration time
                tokenStore.blacklistAccessToken(jti, expirationTimeInSeconds);
            }

            // Remove both access token and refresh token from Redis
            tokenStore.removeRefreshToken(refreshToken);
            tokenStore.removeRevokedToken(accessToken);
        } catch (Exception e) {
            throw new InternalServerErrorException("Something went wrong. Please try again later.");
        }
    }


    public CreateCredentialResponse createCredential(String email, String password, Role role) {
        Optional<Credential> existingCredential = credentialRepository.findByUserId(email);

        if (existingCredential.isPresent()) {
            throw new RuntimeException("Credential already exists");
        }

        Credential newCredential = new Credential(email, role);
        newCredential.encryptCredentialPassword(password, passwordEncoder);
        credentialRepository.save(newCredential);

        return new CreateCredentialResponse(email, "Credentials created");
    }

    private TokenGrant generateAccessToken(String userId, Role role) {
        try {
            String jti = UUID.randomUUID().toString();

            var expirationTime = Date.from(Instant.now().plusSeconds(600));
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(userId)
                    .issuer("http://localhost")
                    .issueTime(new Date())
                    .expirationTime(expirationTime)
                    .jwtID(jti)
                    .claim("username", userId)
                    .claim("roles", role.name())
                    .build();

            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(),
                    claimsSet
            );

            JWSSigner signer = new RSASSASigner(rsaKey.toRSAPrivateKey());
            signedJWT.sign(signer);

            return new TokenGrant(signedJWT.serialize(), expirationTime.getTime());
        } catch (JOSEException e) {
            throw new InternalServerErrorException("Something went wrong.Please try again later");
        }
    }

    private long getRemainingExpirationTime(String accessToken) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(accessToken);
            return (signedJWT.getJWTClaimsSet().getExpirationTime().getTime() - System.currentTimeMillis()) / 1000;
        } catch (Exception e) {
            throw new InternalServerErrorException("Something went wrong.Please try again later");
        }
    }
}
