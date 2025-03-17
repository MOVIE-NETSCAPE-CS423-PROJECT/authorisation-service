package com.movienetscape.authorization.controller;


import com.movienetscape.authorization.dto.request.*;
import com.movienetscape.authorization.dto.response.LoginResponse;
import com.movienetscape.authorization.dto.response.RefreshTokenResponse;
import com.movienetscape.authorization.dto.response.SimpleMessageResponse;
import com.movienetscape.authorization.service.AuthenticationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthorizationController {

    private final AuthenticationService authService;

    private final Logger logger = LoggerFactory.getLogger(AuthorizationController.class);

    public AuthorizationController(AuthenticationService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest request) {
        logger.info("Received login request for username: {}", request.getUsername());
        return authService.validateCredential(request.getUsername(), request.getPassword());
    }

    @PostMapping("/create")
    public ResponseEntity<CreateCredentialResponse> createCredential(@RequestBody CreateCredentialRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.createCredential(request.getEmail(), request.getPassword()));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<RefreshTokenResponse> refreshToken(@RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refreshToken(request.getRefreshToken()));
    }

    @PostMapping("/change-password")
    public ResponseEntity<SimpleMessageResponse> setPassword(@RequestBody ChangePasswordRequest request) {
        return ResponseEntity.status(HttpStatus.OK).body(authService.resetPassword(request));
    }


    @PostMapping("/verify-password-reset-token")
    public ResponseEntity<SimpleMessageResponse> verifyToken(@RequestBody SimpleStringRequest verifyTokenRequest) {
        return ResponseEntity.status(HttpStatus.OK).body(authService.verifyToken(verifyTokenRequest));
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String authorizationHeader, @RequestBody LogoutRequest request) {
        String accessToken = authorizationHeader.replace("Bearer ", "");
        authService.logout(accessToken, request.getRefreshToken());
        return ResponseEntity.ok("logout successful");
    }


    @PostMapping("/forgot-password/{email}")
    public ResponseEntity<SimpleMessageResponse> sendPasswordResetToken(@PathVariable String email) {
        return ResponseEntity.ok(authService.sendTokenToEmail(email));
    }

}