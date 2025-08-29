package com.br.azevedo.security.interceptor;

import com.br.azevedo.exception.ApplicationException;
import com.br.azevedo.exception.AuthenticationException;
import com.br.azevedo.exception.NotFoundException;
import com.br.azevedo.security.EnableSecurity;
import com.br.azevedo.security.JwtSecurity;
import com.br.azevedo.security.config.vault.VaultParameter;
import com.br.azevedo.security.secretManager.VaultSecretManager;
import com.br.azevedo.security.strategy.TokenValidatorFactory;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.net.URI;
import java.util.Arrays;
import java.util.HashSet;
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
    private final TokenValidatorFactory tokenValidatorFactory;
    private HttpServletRequest request;

    public AuthorizationInterceptor(
            ApplicationContext applicationContext,
            Environment environment,
            VaultParameter vaultParameter,
            TokenValidatorFactory tokenValidatorFactory) {
        this.applicationContext = applicationContext;
        this.tokenValidatorFactory = tokenValidatorFactory;
        this.enabledSecurity(environment, vaultParameter);
    }

    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) {

        this.request = request;
        validateAuthorization(request.getHeader(AUTHORIZATION), request);
        validateTransactionId(request.getHeader(TRANSACTION_ID));
        return true;
    }

    private void enabledSecurity(Environment environment, VaultParameter vaultParameter) {
        try {
            log.info("Ativando a Segurança");
            VaultSecretManager vaultSecretManager = new VaultSecretManager(applicationContext, environment, vaultParameter);
            this.jwtService = new JwtSecurity(this.request, vaultSecretManager, tokenValidatorFactory);
            log.info("Segurança ativada");
        } catch (Exception e) {
            log.error("Não foi possivel habilitar a segurança: {}", e.getMessage());
            throw new ApplicationException("Não foi possivel habilitar a segurança", e);
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

    private boolean isOptionsRequest(HttpServletRequest request) {
        return HttpMethod.OPTIONS.name().equals(request.getMethod());
    }

    private boolean isPublicUrl(String url) {
        // 1. Extrai o caminho da URL recebida.
        String path = URI.create(url).getPath();

        // 2. Inicia a coleção de patterns com as URLs públicas padrão.
        Set<Pattern> publicPatterns = new HashSet<>(PUBLIC_URLS);

        // 3. Adiciona os caminhos customizados da anotação, se existirem.
        EnableSecurity enableSecurity = this.getRequestSecurityMetadata(this.applicationContext);
        if (!ObjectUtils.isEmpty(enableSecurity) && !ArrayUtils.isEmpty(enableSecurity.publicPaths())) {
            Arrays.stream(enableSecurity.publicPaths())
                    .map(Pattern::compile)
                    .forEach(publicPatterns::add);
        }

        // 4. Verifica se o caminho corresponde a qualquer um dos padrões.
        return publicPatterns.stream()
                .anyMatch(pattern -> pattern.matcher(path).find());
    }

    private void validateTransactionId(String transactionId) {
        if(!isPublicUrl(request.getRequestURI()) ) {
            if (StringUtils.isEmpty(transactionId)) {
                log.error("The transactionid header is required.");
                throw new NotFoundException("The transactionid header is required.");
            } else if (!UUID_REGEX_PATTERN.matcher(transactionId).matches()){
                log.error("The transactionid [{}] invalid.", transactionId);
                throw new NotFoundException("Invalid transactionid.");
            }
        }
    }

    private EnableSecurity getRequestSecurityMetadata(ApplicationContext applicationContext) {
        return applicationContext.getBeansWithAnnotation(EnableSecurity.class)
                .values()
                .stream()
                .findFirst()
                .map(a -> AnnotationUtils.findAnnotation(a.getClass(), EnableSecurity.class))
                .orElse(null);
    }
}
