package com.movienetscape.authorization.dto.request;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CreateCredentialRequest {
    private String email;
    private String password;
}
