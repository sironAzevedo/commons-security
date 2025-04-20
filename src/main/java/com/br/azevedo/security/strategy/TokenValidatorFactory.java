package com.br.azevedo.security.strategy;

import com.br.azevedo.exception.AuthenticationException;
import com.br.azevedo.security.service.TokenValidationStrategy;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class TokenValidatorFactory {

    private final List<TokenValidationStrategy> strategies;

    public TokenValidatorFactory(List<TokenValidationStrategy> strategies) {
        this.strategies = strategies;
    }

    public TokenValidationStrategy getStrategy(Object token) {
        return strategies.stream()
                .filter(s -> s.supports(token))
                .findFirst()
                .orElseThrow(() -> new AuthenticationException("No strategy found for token type: " + token.getClass()));
    }
}
