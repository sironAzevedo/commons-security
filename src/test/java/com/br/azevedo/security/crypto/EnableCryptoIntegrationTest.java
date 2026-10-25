package com.br.azevedo.security.crypto;

import com.br.azevedo.security.EnableCriptografia;
import com.br.azevedo.security.EnableCrypto;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.services.ssm.SsmClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class EnableCryptoIntegrationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner();

    @Configuration
    @EnableCrypto
    static class TestEnableCryptoConfig {
        @Bean
        public SsmClient ssmClient() {
            return mock(SsmClient.class);
        }
    }

    @Configuration
    @EnableCriptografia
    static class TestEnableCriptografiaConfig {
        @Bean
        public SsmClient ssmClient() {
            return mock(SsmClient.class);
        }
    }

    @Test
    @DisplayName("Deve carregar beans de ICriptografiaService e ICryptoService quando @EnableCrypto estiver presente")
    void shouldLoadCryptoBeansWithEnableCrypto() {
        contextRunner.withUserConfiguration(TestEnableCryptoConfig.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(ICriptografiaService.class);
                    assertThat(context).hasSingleBean(ICryptoService.class);
                });
    }

    @Test
    @DisplayName("Deve carregar beans de ICriptografiaService e ICryptoService quando @EnableCriptografia estiver presente")
    void shouldLoadCryptoBeansWithEnableCriptografia() {
        contextRunner.withUserConfiguration(TestEnableCriptografiaConfig.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(ICriptografiaService.class);
                    assertThat(context).hasSingleBean(ICryptoService.class);
                });
    }
}
