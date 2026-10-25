package com.br.azevedo.security.config;

import com.br.azevedo.exception.ApplicationException;
import com.br.azevedo.infra.aws.AWSCredentialFactory;
import com.br.azevedo.infra.aws.AWSInfraConfig;
import com.br.azevedo.infra.aws.AwsProperties;
import com.br.azevedo.infra.aws.ssm.AwsParameterStoreService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.services.ssm.SsmClient;

/**
 * Configuração de integração da segurança com os serviços AWS do commons-utils.
 * Garante que o AWS SSM Parameter Store esteja disponível para o commons-security,
 * reaproveitando o SsmClient/AwsParameterStoreService caso a aplicação cliente já o tenha habilitado,
 * ou instanciando-o automaticamente a partir das credenciais AWS configuradas.
 */
@Slf4j
@Configuration
@Import({AwsProperties.class, AWSCredentialFactory.class})
public class SecurityAwsConfig {

    @Bean
    @ConditionalOnMissingBean(AwsParameterStoreService.class)
    public AwsParameterStoreService securityAwsParameterStoreService(
            ObjectProvider<SsmClient> ssmClientProvider,
            AwsProperties awsProperties,
            AWSCredentialFactory credentialFactory) {

        SsmClient existingSsmClient = ssmClientProvider.getIfAvailable();
        if (existingSsmClient != null) {
            log.info("commons-security: SsmClient já existente na aplicação cliente detectado. Reaproveitando conexão para acesso ao Parameter Store.");
            return AWSInfraConfig.createParameterStoreService(existingSsmClient);
        }

        log.info("commons-security: SSM não estava previamente habilitado. Inicializando SSM automaticamente via commons-utils.");
        validarConfiguracaoAws(awsProperties);

        try {
            AwsCredentialsProvider credentialsProvider = credentialFactory.getCredentialsProvider();
            SsmClient ssmClient = AWSInfraConfig.createSsmClient(awsProperties, credentialsProvider);
            return AWSInfraConfig.createParameterStoreService(ssmClient);
        } catch (Exception e) {
            log.error("commons-security: Falha ao inicializar o SSM Parameter Store via commons-utils: {}", e.getMessage());
            throw new ApplicationException("Para utilizar @EnableSecurity, é obrigatório configurar as credenciais da AWS (cloud.aws.credentials.access-key e secret-key ou IAM Role) para que o SSM Parameter Store seja acessado via commons-utils.", e);
        }
    }

    private void validarConfiguracaoAws(AwsProperties awsProperties) {
        boolean hasStaticCreds = awsProperties.getCredentials() != null &&
                awsProperties.getCredentials().hasStaticCredentials();

        if (!hasStaticCreds) {
            String envKey = System.getenv("AWS_ACCESS_KEY_ID");
            String envRole = System.getenv("AWS_ROLE_ARN");
            String envContainer = System.getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI");

            if (envKey == null && envRole == null && envContainer == null) {
                log.info("commons-security: Nenhuma credencial estática explícita em 'cloud.aws.credentials'. A resolução será delegada ao DefaultCredentialsProvider da AWS.");
            }
        }
    }
}
