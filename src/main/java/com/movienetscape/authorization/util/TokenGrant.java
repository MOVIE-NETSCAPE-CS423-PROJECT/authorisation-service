package com.movienetscape.authorization.util;




public record TokenGrant(String token, Long expiresIn) {

}
