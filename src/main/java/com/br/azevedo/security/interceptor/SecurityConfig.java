package com.br.azevedo.security.interceptor;

import com.br.azevedo.security.EnableSecurity;
import com.br.azevedo.security.JwtSecurity;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Configuration
@ConditionalOnProperty(
        value = {"security.enabled"},
        havingValue = "true",
        matchIfMissing = true
)
public class SecurityConfig implements WebMvcConfigurer {

    private final EnableSecurity enableSecurity;
    private final JwtSecurity jwtService;

    @Autowired
    public SecurityConfig(ApplicationContext applicationContext, JwtSecurity jwtService) {
        log.info("Segurança ativada");
        this.enableSecurity = getRequestSecurityMetadata(applicationContext);
        this.jwtService = jwtService;
    }

    @Bean
    public AuthorizationInterceptor authorizationInterceptor() {
        return new AuthorizationInterceptor(this.jwtService, getUrlpublics());
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(authorizationInterceptor());
    }

    private Set<String> getUrlpublics() {
        return Arrays.stream(ArrayUtils.addAll(Urls.PUBLIC_URLS, this.enableSecurity.publicPaths()))
                .collect(Collectors.toSet());
    }

    private EnableSecurity getRequestSecurityMetadata(ApplicationContext applicationContext) {
        Object annotatedClass = applicationContext.getBeansWithAnnotation(EnableSecurity.class)
                .values()
                .stream()
                .findFirst()
                .orElseThrow(() -> new ApplicationContextException("Não foi possível achar uma classe com @EnableSecurity"));

        return AnnotationUtils.findAnnotation(annotatedClass.getClass(), EnableSecurity.class);
    }
}
