package com.br.azevedo.security;

import com.br.azevedo.infra.cache.redis.repository.ICacheRepository;
import com.br.azevedo.security.config.vault.VaultParameter;
import com.br.azevedo.security.secretManager.VaultSecretManager;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class EnableVaultTest {

    @Configuration
    @EnableVault
    static class AppWithVaultConfig {
        @Bean
        public ICacheRepository cacheRepository() {
            return mock(ICacheRepository.class);
        }
    }

    @Configuration
    static class AppWithoutVaultConfig {
    }

    @Test
    @DisplayName("Não deve registrar VaultParameter nem VaultSecretManager quando @EnableVault não estiver presente")
    void shouldNotLoadVaultWhenAnnotationNotPresent() {
        new ApplicationContextRunner()
                .withUserConfiguration(AppWithoutVaultConfig.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(VaultParameter.class);
                    assertThat(context).doesNotHaveBean(VaultSecretManager.class);
                });
    }

    @Test
    @DisplayName("Deve registrar beans do Vault quando @EnableVault estiver presente")
    void shouldLoadVaultWhenAnnotationPresent() {
        new ApplicationContextRunner()
                .withUserConfiguration(AppWithVaultConfig.class)
                .withPropertyValues(
                        "security.secret.vault.endpoint=http://localhost:8200",
                        "security.secret.vault.role-id=dummy-role",
                        "security.secret.vault.secret-id=dummy-secret"
                )
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(VaultParameter.class);
                    assertThat(context).hasSingleBean(VaultSecretManager.class);
                });
    }
}
