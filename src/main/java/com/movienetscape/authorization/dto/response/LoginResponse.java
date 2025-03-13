package com.movienetscape.authorization.dto.response;


import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class LoginResponse {
    private String message;
    private String userId;
    private String accessToken;
    private String refreshToken;
    private Long tokenExpiresIn;


}
