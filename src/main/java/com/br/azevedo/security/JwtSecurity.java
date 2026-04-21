package com.br.azevedo.security;

import com.br.azevedo.exception.AuthenticationException;
import com.br.azevedo.security.service.TokenValidationStrategy;
import com.br.azevedo.security.strategy.TokenValidatorFactory;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import static org.apache.commons.lang3.ObjectUtils.isEmpty;

@Slf4j
@Component
public class JwtSecurity {

    @Value("${security.scopes:#{null}}")
    private String scopes;

    private final HttpServletRequest request;
    private final TokenValidatorFactory tokenValidatorFactory;
    private static final String EMPTY_SPACE = " ";
    private static final Integer TOKEN_INDEX = 1;

    public JwtSecurity(HttpServletRequest request,
                       TokenValidatorFactory tokenValidatorFactory) {
        this.request = request;
        this.tokenValidatorFactory = tokenValidatorFactory;
    }

    public void validateAuthorization(String token) {
        try {
            TokenValidationStrategy strategy = tokenValidatorFactory.getStrategy(token);
            strategy.validate(this.request);
        }

//        catch (ExpiredJwtException e) {
//            log.error("Token expirado");
//            throw new AuthenticationException("Token expirado");
//        }

        catch (Exception ex) {
            log.error("Erro ao validar o token: {}", ex.getMessage());
            var msg = StringUtils.defaultIfBlank(ex.getMessage(), "Error while trying to proccess the Access Token.");
            throw new AuthenticationException(msg);
        }
    }

    private static String extractToken(String token) {
        if (isEmpty(token)) {
            throw new AuthenticationException("The access token was not informed.");
        }
        if (token.contains(EMPTY_SPACE)) {
            return token.split(EMPTY_SPACE)[TOKEN_INDEX];
        }
        return token;
    }
}
