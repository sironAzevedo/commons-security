package com.br.azevedo.security.strategy;

import com.br.azevedo.exception.ApplicationException;
import com.br.azevedo.exception.AuthenticationException;
import com.br.azevedo.infra.aws.ssm.AwsParameterStoreService;
import com.br.azevedo.infra.cache.redis.repository.ICacheRepository;
import com.br.azevedo.security.models.jwt.TokenMapper;
import com.br.azevedo.security.secretManager.VaultSecretManager;
import com.br.azevedo.security.service.TokenValidationStrategy;
import com.br.azevedo.utils.EnvironmentUtils;
import com.br.azevedo.utils.JsonUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Fábrica de estratégias de validação de token.
 * Obtém a chave de assinatura (API_SECRET) a partir do AWS SSM Parameter Store
 * no caminho '/auth-api/jwt/credentials-{ambiente}', ou a partir da propriedade
 * 'security.jwt.secret' / variável 'JWT_SECRET', com fallback para o Vault caso habilitado.
 */
@Slf4j
@Component
public class TokenValidatorFactory {

    private final List<TokenValidationStrategy> strategies;
    private final AwsParameterStoreService parameterStoreService;
    private final Environment environment;
    private final ICacheRepository cacheRepository;
    private final ObjectProvider<VaultSecretManager> vaultSecretManagerProvider;

    private static final String PARAMETER_PATH_PATTERN = "/auth-api/jwt/credentials-%s";
    private static final String CACHE_KEY_SECURITY_JWT = "security_jwt_credentials";
    private static final Duration CACHE_TTL = Duration.ofHours(1);

    private static final List<String> DIRECT_SECRET_PROPERTIES = List.of(
            "security.jwt.secret",
            "security.jwt.api-secret",
            "JWT_SECRET",
            "API_SECRET"
    );

    private static final List<String> SECRET_CANDIDATE_KEYS = List.of(
            "API_SECRET", "api_secret", "apiSecret",
            "CLIENT_SECRET", "client_secret", "clientSecret",
            "SECRET", "secret",
            "JWT_SECRET", "jwt_secret", "jwtSecret",
            "SECRET_KEY", "secret_key", "secretKey",
            "VALUE", "value",
            "KEY", "key"
    );

    public TokenValidatorFactory(
            List<TokenValidationStrategy> strategies,
            AwsParameterStoreService parameterStoreService,
            Environment environment,
            ICacheRepository cacheRepository) {
        this(strategies, parameterStoreService, environment, cacheRepository, null);
    }

    @Autowired
    public TokenValidatorFactory(
            List<TokenValidationStrategy> strategies,
            AwsParameterStoreService parameterStoreService,
            Environment environment,
            @Autowired(required = false) ICacheRepository cacheRepository,
            ObjectProvider<VaultSecretManager> vaultSecretManagerProvider) {
        this.strategies = strategies;
        this.parameterStoreService = parameterStoreService;
        this.environment = environment;
        this.cacheRepository = cacheRepository;
        this.vaultSecretManagerProvider = vaultSecretManagerProvider;
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
     * Obtém a chave secreta da API (API_SECRET) para validação e decodificação do JWT.
     *
     * <p>Ordem de Resolução (Clean Code Pipeline):</p>
     * <ol>
     *   <li><b>Segredo Direto:</b> Propriedades {@code security.jwt.secret}, {@code security.jwt.api-secret} ou variáveis de ambiente {@code JWT_SECRET} / {@code API_SECRET}.</li>
     *   <li><b>Cache:</b> Redis ou Ehcache centralizado (chave {@code security_jwt_credentials}).</li>
     *   <li><b>AWS SSM Parameter Store:</b> Busca no caminho {@code security.jwt.ssm-path} ou {@code /auth-api/jwt/credentials-{ambiente}}.</li>
     *   <li><b>Fallback para Vault:</b> Caso o SSM falhe e o {@link VaultSecretManager} esteja ativo via {@code @EnableVault}.</li>
     * </ol>
     *
     * @return Segredo JWT em texto plano
     */
    public String getApiSecret() {
        return resolveDirectJwtSecret()
                .or(this::resolveFromCacheOrExternalSources)
                .orElseThrow(() -> new ApplicationException("Não foi possível resolver o segredo JWT através de nenhuma fonte configurada"));
    }

    private Optional<String> resolveDirectJwtSecret() {
        for (String propertyName : DIRECT_SECRET_PROPERTIES) {
            String secret = environment.getProperty(propertyName);
            if (StringUtils.isNotBlank(secret)) {
                log.debug("Utilizando secret JWT configurado diretamente na propriedade/ambiente: [{}]", propertyName);
                return Optional.of(secret.trim());
            }
        }
        return Optional.empty();
    }

    private Optional<String> resolveFromCacheOrExternalSources() {
        String parameterPath = resolveParameterPath(resolveActiveEnvironment());

        return getFromCache(parameterPath)
                .or(() -> Optional.of(fetchSecretAndCache(parameterPath)));
    }

    private String fetchSecretAndCache(String parameterPath) {
        log.debug("Cache MISS para secret JWT. Buscando no Parameter Store: [{}]", parameterPath);
        String secret = fetchFromSsmOrFallback(parameterPath);
        saveToCache(parameterPath, secret);
        return secret;
    }

    private String fetchFromSsmOrFallback(String parameterPath) {
        try {
            String rawValue = parameterStoreService.getParameter(parameterPath, true);
            return extractApiSecretFromValue(rawValue, parameterPath);
        } catch (Exception ex) {
            log.error("Erro ao buscar secret JWT no Parameter Store no caminho [{}]: {}", parameterPath, ex.getMessage());

            return tryGetSecretFromVaultFallback(parameterPath)
                    .orElseThrow(() -> new ApplicationException(buildDetailedErrorMessage(parameterPath, ex), ex));
        }
    }

    private Optional<String> getFromCache(String parameterPath) {
        if (cacheRepository == null) {
            return Optional.empty();
        }
        try {
            String cached = cacheRepository.getCacheByNameAndKey(CACHE_KEY_SECURITY_JWT, parameterPath, String.class);
            if (StringUtils.isNotBlank(cached)) {
                log.debug("Cache HIT para secret JWT: {}", parameterPath);
                return Optional.of(cached.trim());
            }
        } catch (Exception e) {
            log.warn("Erro ao ler secret JWT do cache: {}", e.getMessage());
        }
        return Optional.empty();
    }

    private void saveToCache(String parameterPath, String secret) {
        if (cacheRepository != null && StringUtils.isNotBlank(secret)) {
            try {
                cacheRepository.saveCacheByNameAndKey(CACHE_KEY_SECURITY_JWT, parameterPath, secret.trim(), CACHE_TTL);
            } catch (Exception e) {
                log.warn("Erro ao salvar secret JWT no cache: {}", e.getMessage());
            }
        }
    }

    private Optional<String> tryGetSecretFromVaultFallback(String parameterPath) {
        if (vaultSecretManagerProvider == null) {
            return Optional.empty();
        }
        try {
            VaultSecretManager vaultSecretManager = vaultSecretManagerProvider.getIfAvailable();
            if (vaultSecretManager != null) {
                log.warn("commons-security: Fallback ativado - buscando secret JWT no Vault (path 'auth')...");
                Map<String, Object> secretMap = vaultSecretManager.getSecret("auth");
                String vaultSecret = extractSecretFromMap(secretMap);
                if (StringUtils.isNotBlank(vaultSecret)) {
                    log.info("commons-security: Secret JWT recuperado com sucesso via fallback do Vault.");
                    return Optional.of(vaultSecret);
                }
            }
        } catch (Exception e) {
            log.warn("commons-security: Falha no fallback do Vault para obtenção de secret JWT: {}", e.getMessage());
        }
        return Optional.empty();
    }

    private String resolveParameterPath(String activeEnv) {
        String customPath = environment.getProperty("security.jwt.ssm-path");
        if (StringUtils.isNotBlank(customPath)) {
            return customPath.contains("%s") ? String.format(customPath, activeEnv) : customPath.trim();
        }
        return String.format(PARAMETER_PATH_PATTERN, activeEnv);
    }

    private String buildDetailedErrorMessage(String parameterPath, Exception ex) {
        String msg = ex.getMessage();
        if (msg != null && (msg.contains("is not authorized to perform: ssm:GetParameter") || msg.contains("AccessDenied"))) {
            return String.format(
                    "Erro ao obter credenciais JWT no Parameter Store (%s): O usuário/role AWS não possui permissão IAM 'ssm:GetParameter' no recurso '%s'. " +
                    "Para solucionar, adicione a política 'ssm:GetParameter' ao IAM User/Role na AWS ou configure a propriedade 'security.jwt.secret' (ou variável JWT_SECRET) na aplicação.",
                    parameterPath, parameterPath
            );
        }
        return String.format("Erro ao obter credenciais JWT no Parameter Store (%s): %s", parameterPath, msg);
    }

    /**
     * Resolve o ambiente ativo delegando para {@link EnvironmentUtils#resolveActiveEnvironment(Environment)}.
     */
    public String resolveActiveEnvironment() {
        return EnvironmentUtils.resolveActiveEnvironment(environment);
    }

    private String extractSecretFromMap(Map<String, Object> map) {
        if (map == null || map.isEmpty()) {
            return null;
        }

        // 1. Busca por chaves prioritárias conhecidas (case-insensitive)
        for (String candidateKey : SECRET_CANDIDATE_KEYS) {
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                if (entry.getKey().equalsIgnoreCase(candidateKey) && entry.getValue() != null) {
                    String candidateVal = entry.getValue().toString().trim();
                    if (StringUtils.isNotBlank(candidateVal)) {
                        return candidateVal;
                    }
                }
            }
        }

        // 2. Se o mapa contiver exatamente 1 par chave-valor com conteúdo textual não-vazio
        if (map.size() == 1) {
            Object singleVal = map.values().iterator().next();
            if (singleVal != null && StringUtils.isNotBlank(singleVal.toString())) {
                return singleVal.toString().trim();
            }
        }

        return null;
    }

    private String extractApiSecretFromValue(String rawValue, String parameterPath) {
        if (StringUtils.isBlank(rawValue)) {
            throw new ApplicationException(String.format("Conteúdo do parâmetro '%s' no Parameter Store está vazio", parameterPath));
        }

        String trimmed = rawValue.trim();
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            try {
                Map<String, Object> map = JsonUtils.jsonToObject(trimmed, Map.class);
                String extracted = extractSecretFromMap(map);
                if (StringUtils.isNotBlank(extracted)) {
                    return extracted;
                }

                // Se o JSON contiver identificador de client mas nenhuma secret reconhecida
                if (map != null && map.keySet().stream().anyMatch(k -> k.equalsIgnoreCase("clientId") || k.equalsIgnoreCase("client_id"))) {
                    throw new ApplicationException(String.format(
                            "Credenciais incompletas no Parameter Store (%s): o JSON contém identificador de client mas não possui nenhuma chave secreta reconhecida (%s)",
                            parameterPath, String.join(", ", SECRET_CANDIDATE_KEYS)
                    ));
                }
            } catch (ApplicationException ae) {
                throw ae;
            } catch (Exception e) {
                log.warn("Falha ao analisar JSON do parâmetro [{}]. Utilizando valor como texto puro.", parameterPath);
            }
        }

        return trimmed;
    }
}
