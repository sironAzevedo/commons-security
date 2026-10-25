package com.br.azevedo.security.config.vault;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;

@Slf4j
@Getter
@Setter
public class VaultParameter {

    @Value("${security.secret.vault.endpoint:http://127.0.0.1:8200}")
    private String vaultUri;

    @Value("${security.secret.vault.role-id:#{null}}")
    private String roleId;

    @Value("${security.secret.vault.secret-id:#{null}}")
    private String secretId;
}
