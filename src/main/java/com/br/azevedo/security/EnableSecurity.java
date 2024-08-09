package com.br.azevedo.security;

import com.br.azevedo.security.interceptor.SecurityConfig;
import com.br.azevedo.security.secretMnager.SecretManagerRepository;
import com.br.azevedo.security.config.VaultSecretsConfig;
import org.springframework.context.annotation.Import;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Import({
        SecurityConfig.class,
        JwtSecurity.class,
        SecretManagerRepository.class,
        VaultSecretsConfig.class})
public @interface EnableSecurity {
    String[] publicPaths() default {};
}
