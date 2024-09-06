package com.br.azevedo.security.secretManager;

import com.br.azevedo.exception.ApplicationException;
import com.br.azevedo.security.config.vault.VaultParameter;
import com.br.azevedo.security.config.vault.VaultSecretsConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.ApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.Versioned;

import java.util.Map;
import java.util.Objects;

@Slf4j
@Component
public class VaultSecretManager {

    private final VaultTemplate vaultTemplate;

    public VaultSecretManager(ApplicationContext applicationContext, Environment environment, VaultParameter vaultParameter) {
        VaultSecretsConfig vaultSecretsConfig = new VaultSecretsConfig(applicationContext, environment);
        this.vaultTemplate = vaultSecretsConfig.vaultTemplate(vaultParameter.getVaultUri(), vaultParameter.getRoleId(), vaultParameter.getSecretId());
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
