package com.br.azevedo.security;

import com.br.azevedo.exception.AuthenticationException;
import com.br.azevedo.security.models.jwt.JwtEntity;
import com.br.azevedo.security.secretMnager.SecretManagerRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import static org.apache.commons.lang3.ObjectUtils.isEmpty;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtSecurity {

    private final SecretManagerRepository secretManagerRepository;

    public void validateAuthorization(String token) {
        try {
            var apiSecret = secretManagerRepository.getSecret("auth").get("API_SECRET").toString();
            var user = JwtEntity.getUser(token, apiSecret);
            if (isEmpty(user) || isEmpty(user.getId())) {
                throw new AuthenticationException("The user is not valid.");
            }
        }

//        catch (ExpiredJwtException e) {
//            log.error("Token expirado");
//            throw new AuthenticationException("Token expirado");
//        }

        catch (Exception ex) {
            log.error("Erro ao validar o token: {}", ex.getMessage());
            throw new AuthenticationException("Error while trying to proccess the Access Token.");
        }
    }
}
