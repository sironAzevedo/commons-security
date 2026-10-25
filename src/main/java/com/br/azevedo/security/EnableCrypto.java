package com.br.azevedo.security;

import com.br.azevedo.security.crypto.config.CryptoConfiguration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Habilita o serviço de criptografia simétrica gerenciada pelo commons-security.
 *
 * <p>Disponibiliza os beans {@link com.br.azevedo.security.crypto.ICriptografiaService}
 * e {@link com.br.azevedo.security.crypto.ICryptoService} no contexto Spring.</p>
 *
 * <p>A chave mestre é obtida do AWS Parameter Store (/app/data/security/cripto-{environment})
 * com cache automático e integração ao AWS SSM.</p>
 *
 * <p>Exemplo de uso:</p>
 * <pre>{@code
 * @EnableCrypto
 * @SpringBootApplication
 * public class Application { ... }
 * }</pre>
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(CryptoConfiguration.class)
public @interface EnableCrypto {
}
