package com.br.azevedo.security.user;

import com.br.azevedo.security.EnableSecurity;
import com.br.azevedo.security.config.AspectConfig;
import org.springframework.context.annotation.Import;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Anotação para validação de usuário por aspecto.
 *
 * @deprecated Esta anotação foi descontinuada em favor da nova anotação única {@link EnableSecurity},
 *             que unifica a segurança global, a segurança por método e a configuração de endpoints públicos.
 */
@Deprecated(since = "1.0", forRemoval = true)
@Documented
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Import({
        AspectConfig.class,
})
public @interface ValidationUser {
}

