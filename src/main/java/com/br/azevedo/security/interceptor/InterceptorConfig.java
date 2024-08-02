package com.br.azevedo.security.interceptor;

import com.br.azevedo.security.EnableSecurity;
import com.br.azevedo.security.JwtSecurity;
import org.apache.commons.lang3.ArrayUtils;
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

@Configuration
@ConditionalOnProperty(
        value = {"security.enabled"},
        havingValue = "true",
        matchIfMissing = true
)
public class InterceptorConfig implements WebMvcConfigurer {

    private final EnableSecurity enablePortoRequestSecurity;

    public InterceptorConfig(ApplicationContext applicationContext) {
        this.enablePortoRequestSecurity = getRequestSecurityMetadata(applicationContext);
    }


    @Bean
    public JwtSecurity jwtService() {
        return new JwtSecurity();
    }

    @Bean
    public AuthInterceptor authInterceptor() {
        return new AuthInterceptor(jwtService(), getUrlpublics());
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(authInterceptor());
    }

    private Set<String> getUrlpublics() {
        return Arrays.stream(ArrayUtils.addAll(Urls.PUBLIC_URLS, this.enablePortoRequestSecurity.publicPaths()))
                .collect(Collectors.toSet());
    }

    private EnableSecurity getRequestSecurityMetadata(ApplicationContext applicationContext) {
        Object annotatedClass = applicationContext.getBeansWithAnnotation(EnableSecurity.class)
                .values()
                .stream()
                .findFirst()
                .orElseThrow(() -> new ApplicationContextException("Não foi possível achar uma classe com @EnablePortoRequestSecurity"));

        return AnnotationUtils.findAnnotation(annotatedClass.getClass(), EnableSecurity.class);
    }
}
