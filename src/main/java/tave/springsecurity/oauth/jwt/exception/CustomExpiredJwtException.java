package tave.springsecurity.oauth.jwt.exception;

import io.jsonwebtoken.ExpiredJwtException;
import lombok.Getter;

@Getter
public class CustomExpiredJwtException extends ExpiredJwtException {
    private final String message;

    public CustomExpiredJwtException(String message, ExpiredJwtException source) {
        super(source.getHeader(), source.getClaims(), source.getMessage());
        this.message = message;
    }
}
