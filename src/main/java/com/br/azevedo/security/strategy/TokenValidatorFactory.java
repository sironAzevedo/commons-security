package com.br.azevedo.security.strategy;

import com.br.azevedo.exception.ApplicationException;
import com.br.azevedo.exception.AuthenticationException;
import com.br.azevedo.infra.aws.ssm.AwsParameterStoreService;
import com.br.azevedo.infra.cache.redis.repository.ICacheRepository;
import com.br.azevedo.security.models.jwt.TokenMapper;
import com.br.azevedo.security.service.TokenValidationStrategy;
import com.br.azevedo.utils.EnvironmentUtils;
import com.br.azevedo.utils.JsonUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Fábrica de estratégias de validação de token.
 * Obtém a chave de assinatura (API_SECRET) a partir do AWS SSM Parameter Store
 * no caminho '/auth-api/jwt/credentials-{ambiente}'.
 */
@Slf4j
@Component
public class TokenValidatorFactory {

    private final List<TokenValidationStrategy> strategies;
    private final AwsParameterStoreService parameterStoreService;
    private final Environment environment;
    private final ICacheRepository cacheRepository;

    private static final String PARAMETER_PATH_PATTERN = "/auth-api/jwt/credentials-%s";
    private static final String CACHE_KEY_SECURITY_JWT = "security_jwt_credentials";
    private static final Duration CACHE_TTL = Duration.ofHours(1);

    @Autowired
    public TokenValidatorFactory(
            List<TokenValidationStrategy> strategies,
            AwsParameterStoreService parameterStoreService,
            Environment environment,
            @Autowired(required = false) ICacheRepository cacheRepository) {
        this.strategies = strategies;
        this.parameterStoreService = parameterStoreService;
        this.environment = environment;
        this.cacheRepository = cacheRepository;
    }

    public TokenValidationStrategy getStrategy(String tokenAuthorization) {
        String apiSecret = getApiSecret();
        Object mapToken = TokenMapper.get(tokenAuthorization, apiSecret);

        TokenValidationStrategy tokenValidationStrategy = strategies.stream()
                .filter(s -> s.supports(mapToken))
                .findFirst()
                .orElseThrow(() -> new AuthenticationException("No strategy found for token type: " + mapToken.getClass()));
        tokenValidationStrategy.setObject(mapToken);

        return tokenValidationStrategy;
    }

    /**
     * Obtém a chave secreta da API (API_SECRET) a partir do Parameter Store.
     * Utiliza cache local/Redis se disponível para evitar latência em cada requisição.
     */
    public String getApiSecret() {
        String activeEnv = EnvironmentUtils.resolveActiveEnvironment(environment);
        String parameterPath = String.format(PARAMETER_PATH_PATTERN, activeEnv);

        // 1. Tentar obter do cache
        if (cacheRepository != null) {
            try {
                String cached = cacheRepository.getCacheByNameAndKey(CACHE_KEY_SECURITY_JWT, parameterPath, String.class);
                if (StringUtils.isNotBlank(cached)) {
                    log.debug("Cache HIT para secret JWT: {}", parameterPath);
                    return cached;
                }
            } catch (Exception e) {
                log.warn("Erro ao ler secret JWT do cache: {}", e.getMessage());
            }
        }

        log.debug("Cache MISS para secret JWT. Buscando no Parameter Store: [{}]", parameterPath);

        // 2. Buscar no SSM Parameter Store
        try {
            String rawValue = parameterStoreService.getParameter(parameterPath, true);
            String apiSecret = extractApiSecretFromValue(rawValue, parameterPath);

            // 3. Salvar no cache
            if (cacheRepository != null && StringUtils.isNotBlank(apiSecret)) {
                try {
                    cacheRepository.saveCacheByNameAndKey(CACHE_KEY_SECURITY_JWT, parameterPath, apiSecret, CACHE_TTL);
                } catch (Exception e) {
                    log.warn("Erro ao salvar secret JWT no cache: {}", e.getMessage());
                }
            }

            return apiSecret;
        } catch (Exception ex) {
            log.error("Erro ao buscar secret JWT no Parameter Store no caminho [{}]: {}", parameterPath, ex.getMessage());
            throw new ApplicationException(String.format("Erro ao obter credenciais JWT no Parameter Store (%s): %s", parameterPath, ex.getMessage()), ex);
        }
    }

    /**
     * Resolve o ambiente ativo a partir de SPRING_PROFILES_ACTIVE ou spring.profiles.active.
     * Caso nenhum seja informado, assume 'dev' como padrão.
     */
    /**
     * Resolve o ambiente ativo delegando para {@link EnvironmentUtils#resolveActiveEnvironment(Environment)}.
     */
    public String resolveActiveEnvironment() {
        return EnvironmentUtils.resolveActiveEnvironment(environment);
    }

    private String extractApiSecretFromValue(String rawValue, String parameterPath) {
        if (StringUtils.isBlank(rawValue)) {
            throw new ApplicationException(String.format("Conteúdo do parâmetro '%s' no Parameter Store está vazio", parameterPath));
        }

        String trimmed = rawValue.trim();
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            try {
                Map<String, Object> map = JsonUtils.jsonToObject(trimmed, Map.class);
                if (map.containsKey("API_SECRET") && map.get("API_SECRET") != null) {
                    return map.get("API_SECRET").toString();
                }
                if (map.containsKey("api_secret") && map.get("api_secret") != null) {
                    return map.get("api_secret").toString();
                }
                if (map.containsKey("secret") && map.get("secret") != null) {
                    return map.get("secret").toString();
                }
            } catch (Exception e) {
                log.warn("Falha ao analisar JSON do parâmetro [{}]. Utilizando valor como texto puro.", parameterPath);
            }
        }

        return trimmed;
    }
}
