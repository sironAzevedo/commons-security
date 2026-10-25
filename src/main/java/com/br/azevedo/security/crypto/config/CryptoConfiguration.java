package com.br.azevedo.security.crypto.config;

import com.br.azevedo.infra.aws.ssm.AwsParameterStoreService;
import com.br.azevedo.security.config.SecurityAwsConfig;
import com.br.azevedo.security.crypto.ICriptografiaService;
import com.br.azevedo.security.crypto.ICryptoService;
import com.br.azevedo.security.crypto.impl.CriptografiaServiceImpl;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.Environment;

/**
 * Configuração Spring carregada exclusivamente ao utilizar {@link com.br.azevedo.security.EnableCrypto}
 * ou {@link com.br.azevedo.security.EnableCriptografia}.
 * Não utiliza @Configuration para evitar auto-detecção acidental por @ComponentScan
 * em aplicações cliente que não utilizam o serviço de criptografia simétrica/assimétrica.
 */
@Import(SecurityAwsConfig.class)
@EnableConfigurationProperties(CryptoProperties.class)
public class CryptoConfiguration {

    @Bean
    @ConditionalOnMissingBean({ICryptoService.class, ICriptografiaService.class})
    public ICryptoService criptografiaService(
            ObjectProvider<AwsParameterStoreService> parameterStoreServiceProvider,
            Environment environment,
            CryptoProperties cryptoProperties) {
        AwsParameterStoreService parameterStoreService = parameterStoreServiceProvider.getIfUnique();
        if (parameterStoreService == null) {
            parameterStoreService = parameterStoreServiceProvider.getIfAvailable();
        }
        return new CriptografiaServiceImpl(parameterStoreService, environment, cryptoProperties);
    }
}
