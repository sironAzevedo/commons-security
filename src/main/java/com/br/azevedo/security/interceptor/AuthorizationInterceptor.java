package com.br.azevedo.security.interceptor;

import com.br.azevedo.exception.AuthenticationException;
import com.br.azevedo.exception.NotFoundException;
import com.br.azevedo.security.EnableSecurity;
import com.br.azevedo.security.JwtSecurity;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextException;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Arrays;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.br.azevedo.security.utils.Constantes.*;

@Slf4j
@Component
@ConditionalOnProperty(
        value = {"security.enabled"},
        havingValue = "true"
)
public class AuthorizationInterceptor implements HandlerInterceptor {

    private final JwtSecurity jwtService;
    private final ApplicationContext applicationContext;

    public AuthorizationInterceptor(ApplicationContext applicationContext, JwtSecurity jwtService) {
        log.info("Segurança ativada");
        this.jwtService = jwtService;
        this.applicationContext = applicationContext;
    }

    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) {

        validateAuthorization(request.getHeader(AUTHORIZATION), request);
        validateTransactionId(request.getHeader(TRANSACTION_ID));
        return true;
    }

    private boolean isPublicUrl(String url) {
        EnableSecurity enableSecurity = this.getRequestSecurityMetadata(applicationContext);
        // Convert the publicPaths array into a set of compiled patterns

        if (ArrayUtils.isEmpty(enableSecurity.publicPaths())) {
            return false;
        }

        Set<Pattern> customPatterns = Arrays.stream(enableSecurity.publicPaths())
                .map(Pattern::compile)
                .collect(Collectors.toSet());

        Set<Pattern> collect = Stream.concat(PUBLIC_URLS.stream(), customPatterns.stream())
                .collect(Collectors.toSet());


        return collect.stream().anyMatch(pattern -> pattern.matcher(url).matches());
    }

    private boolean isOptionsRequest(HttpServletRequest request) {
        return HttpMethod.OPTIONS.name().equals(request.getMethod());
    }

    private void validateTransactionId(String transactionId) {
        if (StringUtils.isEmpty(transactionId)) {
            log.error("The transactionid header is required.");
            throw new NotFoundException("The transactionid header is required.");
        } else if (!UUID_REGEX_PATTERN.matcher(transactionId).matches()){
            log.error("The transactionid [{}] invalid.", transactionId);
            throw new NotFoundException("Invalid transactionid.");
        }
    }

    private void validateAuthorization(String authorization, HttpServletRequest request) {
        if (isOptionsRequest(request) || isPublicUrl(request.getRequestURI())) {
            return;
        } else if (StringUtils.isEmpty(authorization)) {
            log.error("Token não foi enviado");
            throw new AuthenticationException("The access token was not informed.");
        }

        jwtService.validateAuthorization(authorization);
    }

    private String generateServiceId() {
        return UUID.randomUUID().toString();
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
