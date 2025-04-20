package com.br.azevedo.security;

import com.br.azevedo.exception.AuthenticationException;
import com.br.azevedo.exception.AuthorizationException;
import com.br.azevedo.model.dto.UserDTO;
import com.br.azevedo.model.enums.PerfilEnum;
import com.br.azevedo.security.models.jwt.AppEntity;
import com.br.azevedo.security.models.jwt.TokenMapper;
import com.br.azevedo.security.secretManager.VaultSecretManager;
import com.br.azevedo.security.service.TokenValidationStrategy;
import com.br.azevedo.security.strategy.TokenValidatorFactory;
import com.br.azevedo.utils.JsonUtils;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.apache.commons.lang3.ObjectUtils.isEmpty;

@Slf4j
@Component
public class JwtSecurity {

    @Value("${security.scopes:#{null}}")
    private String scopes;

    private final HttpServletRequest request;
    private final VaultSecretManager vaultSecretManager;
    private final TokenValidatorFactory tokenValidatorFactory;
    private static final String EMPTY_SPACE = " ";
    private static final Integer TOKEN_INDEX = 1;

    public JwtSecurity(HttpServletRequest request,
                       VaultSecretManager vaultSecretManager,
                       TokenValidatorFactory tokenValidatorFactory) {
        this.request = request;
        this.vaultSecretManager = vaultSecretManager;
        this.tokenValidatorFactory = tokenValidatorFactory;
    }

    public void validateAuthorization(String token) {
        try {
            var apiSecret = vaultSecretManager.getSecret("auth").get("API_SECRET").toString();
            Object mapToken = TokenMapper.get(token, apiSecret);
            TokenValidationStrategy strategy = tokenValidatorFactory.getStrategy(mapToken);
            strategy.validate(this.request, mapToken);
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
