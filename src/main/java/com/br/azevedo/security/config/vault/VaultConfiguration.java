package com.br.azevedo.security.config.vault;

import com.br.azevedo.infra.cache.redis.repository.ICacheRepository;
import com.br.azevedo.security.secretManager.VaultSecretManager;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.vault.core.VaultTemplate;

/**
 * Configuração independente para o HashiCorp Vault.
 * Carregada exclusivamente quando a anotação @EnableVault está presente.
 * Não utiliza @Configuration para evitar auto-detecção acidental por @ComponentScan
 * em aplicações cliente que não utilizam o Vault.
 */
public class VaultConfiguration {

    @Bean
    @ConditionalOnMissingBean(VaultParameter.class)
    public VaultParameter vaultParameter() {
        return new VaultParameter();
    }

    @Bean
    @ConditionalOnMissingBean(VaultSecretManager.class)
    public VaultSecretManager vaultSecretManager(
            ApplicationContext applicationContext,
            Environment environment,
            VaultParameter vaultParameter,
            ObjectProvider<ICacheRepository> cacheRepositoryProvider) {
        return new VaultSecretManager(applicationContext, environment, vaultParameter, cacheRepositoryProvider.getIfAvailable());
    }
}
