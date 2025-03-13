package com.movienetscape.authorization.util.exception;


public class TokenExpiredException  extends RuntimeException {

    private final String message;

    public TokenExpiredException(String message) {
        this.message = message;
    }
}
