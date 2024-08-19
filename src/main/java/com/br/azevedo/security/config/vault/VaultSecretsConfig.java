package com.br.azevedo.security.config.vault;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultToken;

@Slf4j
@Configuration
@RequiredArgsConstructor
@ConditionalOnProperty(
        value = {"security.enabled"},
        havingValue = "true",
        matchIfMissing = true
)
public class VaultSecretsConfig {

    private final ApplicationContext applicationContext;
    private final Environment environment;

    @Value("${security.secret.vault.endpoint:http://127.0.0.1:8200}")
    private String vaultUri;

    @Value("${security.secret.vault.role-id}")
    private String roleId;

    @Value("${security.secret.vault.secret-id}")
    private String secretId;

    @Bean
    public VaultTemplate vaultTemplate() {
        try {
            AppRoleAuthenticationService appRoleAuth = new AppRoleAuthenticationService(roleId, secretId, vaultUri, applicationContext);
            VaultEndpoint vaultEp = appRoleAuth.vaultEndpoint();
            VaultToken auth = appRoleAuth.clientAuthentication().login();

            if (environment instanceof StandardEnvironment) {
                ((StandardEnvironment) environment).getSystemProperties().put("spring.cloud.vault.token", auth.getToken());
            }
            return new VaultTemplate(vaultEp, new TokenAuthentication(auth.getToken()));

        } catch (Exception e) {
            throw new RuntimeException("Erro ao configurar o Vault", e);
        }
    }
}
