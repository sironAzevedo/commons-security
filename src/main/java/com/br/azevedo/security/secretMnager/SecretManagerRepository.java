package com.br.azevedo.security.secretMnager;

import com.br.azevedo.exception.ApplicationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Repository;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.Versioned;

import java.util.Map;
import java.util.Objects;

@Slf4j
@Repository
@RequiredArgsConstructor
@ConditionalOnProperty(
        value = {"security.enabled"},
        havingValue = "true"
)
public class SecretManagerRepository {
    private final VaultTemplate vaultTemplate;

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

    @SuppressWarnings("unchecked")
    @Cacheable(value = "vault_secret_by_path", key = "#path", unless="#result == null")
    public Map<String, Object> getSecret(String path) {
        return (Map<String, Object>) Objects.requireNonNull(
                Objects.requireNonNull(vaultTemplate.read("secret/data/".concat(path)))
                        .getData()).get("data");
    }

    @CacheEvict(value = "vault_secret_by_path", key = "#path", allEntries = true)
    public void deleteSecret(String path) {
        try {
            vaultTemplate.delete(path);
            log.info("Secret deleted: {}", path);
        } catch (Exception e) {
            throw new ApplicationException("Erro ao deletar secret - ".concat(e.getMessage()));
        }
    }
}
