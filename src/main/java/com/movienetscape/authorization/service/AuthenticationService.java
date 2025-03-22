package com.movienetscape.authorization.service;

import com.movienetscape.authorization.dto.request.CreateCredentialResponse;
import com.movienetscape.authorization.dto.request.ChangePasswordRequest;
import com.movienetscape.authorization.dto.request.SimpleStringRequest;
import com.movienetscape.authorization.dto.response.LoginResponse;
import com.movienetscape.authorization.dto.response.RefreshTokenResponse;
import com.movienetscape.authorization.dto.response.SimpleMessageResponse;
import com.movienetscape.authorization.messaging.event.PasswordResetEvent;
import com.movienetscape.authorization.messaging.producer.KafkaEventProducer;
import com.movienetscape.authorization.model.TokenVerification;
import com.movienetscape.authorization.repository.TokenRepository;
import com.movienetscape.authorization.util.TokenGenerator;
import com.movienetscape.authorization.util.enums.Role;
import com.movienetscape.authorization.util.exception.*;
import com.movienetscape.authorization.model.UserCredential;
import com.movienetscape.authorization.repository.CredentialRepository;
import com.movienetscape.authorization.util.TokenGrant;
import com.movienetscape.usermanagementservice.util.exception.BadRequestException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Service
@Transactional
@RequiredArgsConstructor
public class AuthenticationService {

    private final CredentialRepository credentialRepository;
    private final PasswordEncoder passwordEncoder;
    private final RSAKey rsaKey;
    private final TokenStoreService tokenStore;
    private final TokenRepository tokenRepository;

    private final KafkaEventProducer kafkaEventProducer;


    public LoginResponse validateCredential(String userId, String password) {

        return credentialRepository.findByUserId(userId)
                .map(userCredential -> {
                    if (userCredential.validatePassword(password, passwordEncoder)) {
                        var accessToken = generateAccessToken(userId, Role.USER);
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


    public SimpleMessageResponse resetPassword(ChangePasswordRequest request) {
        UserCredential user = credentialRepository.findByUserId(request.getEmail())
                .orElseThrow(() -> new NotFoundException("Email not found: " + request.getEmail()));

//         if ()tokenRepository.findTokenVerificationByUserId(request.getEmail());

        user.changePassword(passwordEncoder.encode(request.getNewPassword()));
        credentialRepository.save(user);
        return new SimpleMessageResponse("Password changed successfully");

    }


    public SimpleMessageResponse verifyToken(SimpleStringRequest simpleStringRequest) {
        TokenVerification tokenVerification = tokenRepository.findTokenVerificationByToken(
                simpleStringRequest.getData());
        if (tokenVerification == null) {
            throw new BadRequestException("Invalid Token");
        }
        if (!isTokenValid(tokenVerification)) throw new TokenExpiredException("Token has expired");

        tokenRepository.delete(tokenVerification);

        return new SimpleMessageResponse("Token verified successfully");
    }

    private boolean isTokenValid(TokenVerification verification) {
        return verification.getTokenExpirationTime().isAfter(LocalDateTime.now()) && !verification.isVerified();
    }

    public SimpleMessageResponse sendTokenToEmail(String email) {
        UserCredential user = credentialRepository.findByUserId(email)
                .orElseThrow(() -> new NotFoundException("Invalid email: " + email));
        String token = TokenGenerator.generateToken();

        TokenVerification verification = TokenVerification.builder()
                .userId(user.getUserId())
                .token(token)
                .tokenExpirationTime(LocalDateTime.now().plusMinutes(10))
                .verified(false)
                .build();

        tokenRepository.save(verification);

        kafkaEventProducer.publishPasswordResetEvent(
                PasswordResetEvent.builder()
                        .token(token)
                        .emailAddress(email)
                        .build()
        );

        return new SimpleMessageResponse("Password reset token has be sent successfully to email: " + email);

    }

    public RefreshTokenResponse refreshToken(String refreshToken) {
        String userId = tokenStore.getUserIdByRefreshToken(refreshToken);

        if (userId == null) {
            throw new TokenExpiredException("Invalid RefreshToken. Please log in again.");
        }

        UserCredential userCredential = credentialRepository.findByUserId(userId)
                .orElseThrow(() -> new NotFoundException("User not found"));

        String oldAccessToken = extractOldAccessTokenFromRedis(userId);
        if (oldAccessToken != null) {
            try {
                SignedJWT signedJWT = SignedJWT.parse(oldAccessToken);
                String jti = signedJWT.getJWTClaimsSet().getJWTID();
                if (jti != null) {
                    long expirationTimeInSeconds = getRemainingExpirationTime(oldAccessToken);
                    tokenStore.blacklistAccessToken(jti, expirationTimeInSeconds);
                }
            } catch (Exception e) {
                throw new RuntimeException("Failed to parse old access token", e);
            }
        }


        var newAccessTokenGrant = generateAccessToken(userId, Role.USER);
        var newResourceToken = generateRefreshToken(userId);


        tokenStore.removeRefreshToken(refreshToken);


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
                tokenStore.blacklistAccessToken(jti, expirationTimeInSeconds);
            }

            tokenStore.removeRefreshToken(refreshToken);
            tokenStore.removeRevokedToken(accessToken);
        } catch (Exception e) {
            throw new InternalServerErrorException("Something went wrong. Please try again later.");
        }
    }


    public CreateCredentialResponse createCredential(String email, String password) {
        Optional<UserCredential> existingCredential = credentialRepository.findByUserId(email);

        if (existingCredential.isPresent()) {
            throw new RecordExistAlreadyException("Credential already exists");
        }

        UserCredential newUserCredential = new UserCredential();
        newUserCredential.setUserId(email);
        newUserCredential.encryptCredentialPassword(password, passwordEncoder);
        credentialRepository.save(newUserCredential);
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
                    .claim("role", role.name())
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
