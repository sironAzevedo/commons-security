package com.br.azevedo.security.secretManager;

import com.br.azevedo.exception.ApplicationException;
import com.br.azevedo.infra.cache.redis.repository.ICacheRepository;
import com.br.azevedo.security.config.vault.VaultParameter;
import com.br.azevedo.security.config.vault.VaultSecretsConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.vault.config.VaultHealthIndicator;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.Versioned;

import java.time.Duration;
import java.util.Map;
import java.util.Objects;

@Slf4j
@Configuration
public class VaultSecretManager {

    private final VaultTemplate vaultTemplate;
    private final ICacheRepository cacheRepository;
    public static final String SECRET_DATA_PATH = "secret/data/";
    private final String KEY_CACHE_VAULT_DEFAULT = "vault_secret_by_path";
    private static final Duration CACHE_TTL = Duration.ofDays(6);

    public VaultSecretManager(
            ApplicationContext applicationContext,
            Environment environment,
            VaultParameter vaultParameter,
            ICacheRepository cacheRepository) {
        this.cacheRepository = cacheRepository;
        VaultSecretsConfig vaultSecretsConfig = new VaultSecretsConfig(applicationContext, environment);
        this.vaultTemplate = vaultSecretsConfig.vaultTemplate(vaultParameter.getVaultUri(), vaultParameter.getRoleId(), vaultParameter.getSecretId());
    }

    @Bean
    public VaultTemplate vaultTemplate() {
        return this.vaultTemplate;
    }

    @Bean
    public VaultHealthIndicator vaultHealthIndicator(VaultTemplate vaultTemplate) {
        return new VaultHealthIndicator(vaultTemplate);
    }

    public void createOrUpdateSecret(String path, Map<String, Object> data) {
        try {

            Versioned.Metadata createResponse = vaultTemplate
                    .opsForVersionedKeyValue("secret")
                    .put(path, data);

            log.info("Secret written successfully. {}", createResponse.getVersion());
        } catch (Exception e) {
            throw new ApplicationException("Erro ao criar ou atualizar secret - ".concat(e.getMessage()));
        }
    }

    public void deleteSecret(String path) {
        try {
            vaultTemplate.delete(path);
            cacheRepository.removeCacheByNameAndKey(KEY_CACHE_VAULT_DEFAULT, path);
            log.info("Secret deleted: {}", path);
        } catch (Exception e) {
            throw new ApplicationException("Erro ao deletar secret - ".concat(e.getMessage()));
        }
    }

    public Map<String, Object> getSecret(String path) {
        return getSecret(path, CACHE_TTL);
    }

    public Map<String, Object> getSecret(String path, Duration ttl) {
        // 1. Cache first
        Map<String, Object> cached = getFromCache(path);
        if (!cached.isEmpty()) {
            log.debug("Cache HIT para path: {}", path);
            return cached;
        }

        log.debug("Cache MISS para path: {}, buscando no Vault", path);

        try {
            Map<String, Object> secret = fetchFromVault(path);
            cacheIfValid(path, secret, ttl);

            return secret;

        } catch (Exception ex) {
            log.error("Erro ao buscar secret no Vault. path={}", path, ex);
            return Map.of();
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> getFromCache(String path) {
        var cache = cacheRepository.getCacheByNameAndKey(
                KEY_CACHE_VAULT_DEFAULT,
                path,
                Map.class
        );

        return (cache != null && !cache.isEmpty()) ? cache : Map.of();
    }

    private Map<String, Object> fetchFromVault(String path) {

        var response = vaultTemplate.read(SECRET_DATA_PATH + path);

        if (response.getData() == null) {
            log.warn("Secret não encontrado no Vault para path: {}", path);
            return Map.of();
        }

        Object rawData = response.getData().get("data");

        if (!(rawData instanceof Map<?, ?> rawMap)) {
            log.error("Formato inesperado do secret no Vault. path={}", path);
            return Map.of();
        }

        return castToMap(rawMap);
    }

    private void cacheIfValid(String path, Map<String, Object> data, Duration ttl) {
        if (!isCacheHit(data)) return;

        cacheRepository.saveCacheByNameAndKey(
                KEY_CACHE_VAULT_DEFAULT,
                path,
                data,
                ttl
        );
    }

    private boolean isCacheHit(Map<String, Object> cache) {
        return cache != null && !cache.isEmpty();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> castToMap(Map<?, ?> rawMap) {
        return (Map<String, Object>) rawMap;
    }
}
