package com.movienetscape.authorization.service;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class TokenStoreService {

    private final RedisTemplate<String, String> redisTemplate;

    public TokenStoreService(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    // Store the refresh token with a 5-minute expiry
    public void storeRefreshToken(String refreshToken, String userId) {
        redisTemplate.opsForValue().setIfAbsent("refresh:" + refreshToken, userId, 400, TimeUnit.SECONDS);
    }

    // Get the user ID linked to the refresh token
    public String getUserIdByRefreshToken(String refreshToken) {
        return redisTemplate.opsForValue().get("refresh:" + refreshToken);
    }

    // Remove the refresh token from Redis when logging out
    public void removeRefreshToken(String refreshToken) {
        redisTemplate.delete("refresh:" + refreshToken);
    }

    public void blacklistAccessToken(String jti, long expirationTimeInSeconds) {
        redisTemplate.opsForValue().setIfAbsent("blacklist:" + jti, "revoked", expirationTimeInSeconds, TimeUnit.SECONDS);
    }

    public boolean isTokenRevoked(String jti) {
        return redisTemplate.opsForValue().get("blacklist:" + jti) != null;
    }

    public void storeAccessToken(String userId, String accessToken, long expirationTimeInSeconds) {
        redisTemplate.opsForValue().set("access:" + userId, accessToken, expirationTimeInSeconds, TimeUnit.SECONDS);
    }

    public String getAccessTokenForUser(String userId) {
        return redisTemplate.opsForValue().get("access:" + userId);
    }

    // Remove the access token when it is revoked
    public void removeRevokedToken(String accessToken) {
        redisTemplate.delete("access:" + accessToken);
    }
}
