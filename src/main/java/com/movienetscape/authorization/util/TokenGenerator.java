package com.movienetscape.authorization.util;

import java.security.SecureRandom;

public class TokenGenerator {
    private static final SecureRandom secureRandom = new SecureRandom();

    public static String generateToken() {
        byte[] randomBytes = new byte[4];
        secureRandom.nextBytes(randomBytes);
        int token = Math.abs(bytesToInt(randomBytes)) % 1_000_000;
        return String.format("%06d", token);
    }

    private static int bytesToInt(byte[] bytes) {
        int result = 0;
        for (byte aByte : bytes) {
            result = (result << 8) | (aByte & 0xFF);
        }
        return result;
    }
}
