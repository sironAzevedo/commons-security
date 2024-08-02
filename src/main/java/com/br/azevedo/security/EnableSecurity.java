package com.br.azevedo.security;

import com.br.azevedo.security.interceptor.InterceptorConfig;
import org.springframework.context.annotation.Import;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Import({InterceptorConfig.class})
public @interface EnableSecurity {
    String[] publicPaths() default {};
}
