package com.br.azevedo.security.config.vault;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultToken;

@Slf4j
public class VaultSecretsConfig {

    private final ApplicationContext applicationContext;
    private final Environment environment;

    public VaultSecretsConfig(ApplicationContext applicationContext, Environment environment) {
        this.applicationContext = applicationContext;
        this.environment = environment;
    }

    public VaultTemplate vaultTemplate(String vaultUri, String roleId, String secretId) {
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
