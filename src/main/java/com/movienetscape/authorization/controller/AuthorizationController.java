package com.movienetscape.authorization.controller;


import com.movienetscape.authorization.dto.request.*;
import com.movienetscape.authorization.dto.response.LoginResponse;
import com.movienetscape.authorization.dto.response.RefreshTokenResponse;
import com.movienetscape.authorization.model.Role;
import com.movienetscape.authorization.service.AuthorisationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthorizationController {

    private final AuthorisationService authService;

    private final Logger logger = LoggerFactory.getLogger(AuthorizationController.class);

    public AuthorizationController(AuthorisationService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest request) {
        logger.info("Received login request for username: {}", request.getUsername());
        return authService.validateCredential(request.getUsername(), request.getPassword());
    }

    @PostMapping("/create")
    public CreateCredentialResponse createCredential(@RequestBody CreateCredentialRequest request) {
        return authService.createCredential(request.getEmail(), request.getPassword(), Role.USER);
    }

    @PostMapping("/refreshtoken")
    public RefreshTokenResponse refreshToken(@RequestBody RefreshTokenRequest request) {
        return authService.refreshToken(request.getRefreshToken());
    }


    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String authorizationHeader, @RequestBody LogoutRequest request) {
        String accessToken = authorizationHeader.replace("Bearer ", "");
        authService.logout(accessToken, request.getRefreshToken());
        return ResponseEntity.ok("Logout successful");
    }


}