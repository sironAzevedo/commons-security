package com.br.azevedo.security.interceptor;

import com.br.azevedo.exception.ApplicationException;
import com.br.azevedo.exception.AuthenticationException;
import com.br.azevedo.exception.NotFoundException;
import com.br.azevedo.security.EnableSecurity;
import com.br.azevedo.security.JwtSecurity;
import com.br.azevedo.security.config.vault.VaultParameter;
import com.br.azevedo.security.secretManager.VaultSecretManager;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextException;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Arrays;
import java.util.Set;
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

    private JwtSecurity jwtService;
    private final ApplicationContext applicationContext;

    public AuthorizationInterceptor(
            ApplicationContext applicationContext,
            Environment environment,
            VaultParameter vaultParameter) {
        this.applicationContext = applicationContext;
        this.enabledSecurity(environment, vaultParameter);
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
        if (ObjectUtils.isEmpty(enableSecurity) || ArrayUtils.isEmpty(enableSecurity.publicPaths())) {
            return false;
        }

        // Convert the publicPaths array into a set of compiled patterns
        Set<Pattern> customPatterns = Arrays.stream(enableSecurity.publicPaths())
                .map(Pattern::compile)
                .collect(Collectors.toSet());

        Set<Pattern> collect = Stream.concat(PUBLIC_URLS.stream(), customPatterns.stream())
                .collect(Collectors.toSet());


        return collect.stream().anyMatch(pattern -> pattern.matcher(url).matches());
    }

    private void enabledSecurity(Environment environment, VaultParameter vaultParameter) {
        try {
            log.info("Ativando a Segurança");
            VaultSecretManager vaultSecretManager = new VaultSecretManager(applicationContext, environment, vaultParameter);
            this.jwtService = new JwtSecurity(vaultSecretManager);
            log.info("Segurança ativada");
        } catch (Exception e) {
            log.error("Não foi possivel habilitar a segurança: {}", e.getMessage());
            throw new ApplicationException("Não foi possivel habilitar a segurança", e);
        }
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

    private EnableSecurity getRequestSecurityMetadata(ApplicationContext applicationContext) {
        return applicationContext.getBeansWithAnnotation(EnableSecurity.class)
                .values()
                .stream()
                .findFirst()
                .map(a -> AnnotationUtils.findAnnotation(a.getClass(), EnableSecurity.class))
                .orElse(null);

//        return AnnotationUtils.findAnnotation(annotatedClass.getClass(), EnableSecurity.class);
    }
}
