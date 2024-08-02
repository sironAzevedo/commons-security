package com.br.azevedo.security.secretMnager;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ObjectUtils;
import org.springframework.vault.VaultException;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.Versioned;

import java.util.Map;

@Slf4j
public class VaultSecretsManager {

    private static final String VAULT_TOKEN = "s.AfKqVJZjngy3dMHqa53Mkrj5";
    private static VaultTemplate vaultTemplate;

    static {
        try {
            VaultEndpoint vaultEndpoint = new VaultEndpoint();
            vaultEndpoint.setHost("127.0.0.1");
            vaultEndpoint.setPort(8200);
            vaultEndpoint.setScheme("http");

            vaultTemplate = new VaultTemplate(
                    vaultEndpoint,
                    new TokenAuthentication(VAULT_TOKEN)
            );
        } catch (VaultException e) {
            e.printStackTrace();
        }
    }

    public static void createOrUpdateSecret(String path, Map<String, Object> data) {
        try {
            Versioned.Metadata createResponse = vaultTemplate
                    .opsForVersionedKeyValue("secret")
                    .put(path, data);

            log.info("Secret written successfully. {}", createResponse.getVersion());
        } catch (VaultException e) {
            e.printStackTrace();
        }
    }

    public static Map<String, Object> getSecret(String path) {
        Versioned<Map<String, Object>> readResponse = vaultTemplate
                .opsForVersionedKeyValue("secret")
                .get(path);

        if (ObjectUtils.isEmpty(readResponse)) {
            return null;
        }
        return readResponse.getData();
    }

    public static void deleteSecret(String path) {
        try {

            vaultTemplate.delete(path);
            log.info("Secret deleted: {}", path);
        } catch (VaultException e) {
            e.printStackTrace();
        }
    }
}
