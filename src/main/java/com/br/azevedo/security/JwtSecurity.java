package com.br.azevedo.security;

import com.br.azevedo.exception.AuthenticationException;
import com.br.azevedo.security.models.jwt.JwtEntity;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import static org.apache.commons.lang3.ObjectUtils.isEmpty;

@Slf4j
@Component
public class JwtSecurity {

    //@Value("${app-config.secrets.api-secret}")
    private String apiSecret;

    public void validateAuthorization(String token) {
        try {
            var user = JwtEntity.getUser(token, apiSecret);
            if (isEmpty(user) || isEmpty(user.getId())) {
                throw new AuthenticationException("The user is not valid.");
            }
        } catch (ExpiredJwtException e) {
            log.error("Token expirado");
            throw new AuthenticationException("Token expirado");
        } catch (Exception ex) {
            log.error("Erro ao validar o token: {}", ex.getMessage());
            throw new AuthenticationException("Error while trying to proccess the Access Token.");
        }
    }
}
