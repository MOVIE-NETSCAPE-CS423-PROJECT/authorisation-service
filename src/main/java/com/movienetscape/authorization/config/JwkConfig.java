package com.movienetscape.authorization.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
public class JwkConfig {

    @Bean
    public RSAKey jwkConfigs(RedisTemplate<String, String> redisTemplate) throws Exception {
        String cachedKey = redisTemplate.opsForValue().get("auth-server-rsa-key");

        if (cachedKey != null) {
            return RSAKey.parse(cachedKey);
        }

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();

        redisTemplate.opsForValue().set("auth-server-rsa-key", rsaKey.toJSONString());
        return rsaKey;
    }


    @Bean
    public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) ->  jwkSelector.select(jwkSet);
    }

    @Bean
    public JWKSet jwkSet(RSAKey rsaKey) {
        return new JWKSet(rsaKey);
    }
}
