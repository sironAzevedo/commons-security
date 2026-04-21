package com.br.azevedo.security.strategy;

import com.br.azevedo.exception.AuthenticationException;
import com.br.azevedo.security.models.jwt.TokenMapper;
import com.br.azevedo.security.secretManager.VaultSecretManager;
import com.br.azevedo.security.service.TokenValidationStrategy;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class TokenValidatorFactory {

    private final List<TokenValidationStrategy> strategies;
    private final VaultSecretManager vaultSecretManager;

    public TokenValidatorFactory(List<TokenValidationStrategy> strategies,
                                 VaultSecretManager vaultSecretManager) {
        this.strategies = strategies;
        this.vaultSecretManager = vaultSecretManager;
    }

    public TokenValidationStrategy getStrategy(String tokenAuthorization) {
        var apiSecret = vaultSecretManager.getSecret("auth").get("API_SECRET").toString();
        Object mapToken = TokenMapper.get(tokenAuthorization, apiSecret);

        TokenValidationStrategy tokenValidationStrategy = strategies.stream()
                .filter(s -> s.supports(mapToken))
                .findFirst()
                .orElseThrow(() -> new AuthenticationException("No strategy found for token type: " + mapToken.getClass()));
        tokenValidationStrategy.setObject(mapToken);

        return tokenValidationStrategy;
    }
}
