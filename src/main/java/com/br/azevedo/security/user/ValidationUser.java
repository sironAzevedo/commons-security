package com.br.azevedo.security.user;

import com.br.azevedo.security.config.AspectConfig;
import com.br.azevedo.security.secretMnager.SecretManagerRepository;
import com.br.azevedo.security.secretMnager.VaultSecretsConfig;
import org.springframework.context.annotation.Import;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Import({
        AspectConfig.class,
})
public @interface ValidationUser {
}
