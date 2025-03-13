package com.movienetscape.authorization.controller;

import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class JwksController {
    private final JWKSet jwkSet;

    public JwksController(JWKSet jwkSet) {
        this.jwkSet = jwkSet;
    }

    @GetMapping("/key/jwks")
    public String getJwks() {
        return jwkSet.toPublicJWKSet().toString();
    }
}
