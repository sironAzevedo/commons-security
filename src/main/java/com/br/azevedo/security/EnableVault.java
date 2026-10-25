package com.br.azevedo.security;

import com.br.azevedo.security.config.vault.VaultConfiguration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Habilita a integração com o HashiCorp Vault de forma desacoplada da segurança principal.
 *
 * <p>Quando anotado em uma classe de configuração ou na classe principal da aplicação cliente,
 * ativa o {@link com.br.azevedo.security.secretManager.VaultSecretManager} e as configurações do Vault.</p>
 *
 * <p>Exemplo de uso:</p>
 * <pre>{@code
 * @EnableVault
 * @SpringBootApplication
 * public class Application { ... }
 * }</pre>
 *
 * <p>Configuração via application.yml:</p>
 * <pre>{@code
 * security:
 *   secret:
 *     vault:
 *       endpoint: ${VAULT_ENDPOINT:http://localhost:8200}
 *       role-id: ${VAULT_ROLE_ID}
 *       secret-id: ${VAULT_SECRET_ID}
 * }</pre>
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(VaultConfiguration.class)
public @interface EnableVault {
}
