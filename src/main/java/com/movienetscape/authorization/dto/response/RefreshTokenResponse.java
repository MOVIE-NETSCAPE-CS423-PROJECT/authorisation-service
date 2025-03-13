package com.movienetscape.authorization.dto.response;


import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class RefreshTokenResponse {
    private String accessToken;
    private String refreshToken;
    private Long tokenExpiresIn;
}
