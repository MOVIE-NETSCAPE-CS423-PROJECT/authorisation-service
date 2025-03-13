package com.movienetscape.authorization.util.exception;


import com.movienetscape.authorization.dto.response.LoginResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;


@RestControllerAdvice
public class GlobalExceptionHandler {

    private final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(value = {LoginException.class})
    public ResponseEntity<LoginResponse> handleLoginException(LoginException exception) {

        logger.error("LoginException occurred: {}", exception.getMessage(), exception);

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .contentType(MediaType.APPLICATION_JSON)
                .body(new LoginResponse(null,
                        null,
                        exception.getMessage(),
                        null,
                        null));

    }


    @ExceptionHandler(TokenExpiredException.class)
    public ResponseEntity<String> handleTokenExpiredException(Exception ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ex.getMessage());
    }


    @ExceptionHandler(InternalServerErrorException.class)
    public ResponseEntity<String> handleInternalServerErrorException(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ex.getMessage());
    }
}
