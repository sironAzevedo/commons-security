package com.br.azevedo.security;

import com.br.azevedo.security.crypto.config.CryptoConfiguration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Alias em português para {@link EnableCrypto}.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(CryptoConfiguration.class)
public @interface EnableCriptografia {
}
