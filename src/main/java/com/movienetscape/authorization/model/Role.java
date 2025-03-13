package com.movienetscape.authorization.model;


public enum Role {
    USER("User"), ADMIN("Admin");


    private final String name;

    Role(String name) {
        this.name = name;
    }
}
