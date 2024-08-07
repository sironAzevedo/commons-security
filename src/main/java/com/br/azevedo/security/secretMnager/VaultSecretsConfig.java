package com.br.azevedo.security.secretMnager;

import com.br.azevedo.exception.InternalErrorException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.core.VaultTemplate;

import java.net.URI;

@Slf4j
@Configuration
public class VaultSecretsConfig {

    @Value("${security.secret.vault.endpoint:http://127.0.0.1:8200}")
    private String vaultEndpoint;

    @Value("${security.secret.vault.token}")
    private String token;

    @Bean(name = "vaultTemplate")
    public VaultTemplate vaultTemplate() {
        try {
            return new VaultTemplate(
                    VaultEndpoint.from(new URI(vaultEndpoint)),
                    new TokenAuthentication(token)
            );
        } catch (Exception e) {
            throw new InternalErrorException("Erro ao configurar o Vault - ".concat(e.getMessage()));
        }
    }
}
