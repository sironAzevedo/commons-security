package com.br.azevedo.security.interceptor;

import com.br.azevedo.exception.ApplicationException;
import com.br.azevedo.exception.AuthenticationException;
import com.br.azevedo.exception.NotFoundException;
import com.br.azevedo.infra.cache.redis.repository.ICacheRepository;
import com.br.azevedo.security.EnableSecurity;
import com.br.azevedo.security.JwtSecurity;
import com.br.azevedo.security.audit.SecurityAuditLogger;
import com.br.azevedo.security.config.vault.VaultParameter;
import com.br.azevedo.security.strategy.TokenValidatorFactory;
import com.br.azevedo.security.utils.SecurityMetadataResolver;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import static com.br.azevedo.security.utils.Constantes.AUTHORIZATION;
import static com.br.azevedo.security.utils.Constantes.TRANSACTION_ID;
import static com.br.azevedo.security.utils.Constantes.UUID_REGEX_PATTERN;

/**
 * Interceptor de autorização do Spring MVC responsável por centralizar a validação de segurança
 * com base na anotação {@link EnableSecurity}.
 *
 * <p><b>Regra de Funcionamento e Precedência:</b></p>
 * <ol>
 *   <li><b>Requisições OPTIONS:</b> Liberadas automaticamente para suporte a CORS pre-flight.</li>
 *   <li><b>Endpoints Públicos:</b> Se o endpoint for considerado público via {@link #isPublicUrl(String)},
 *       ou pelas propriedades {@code publicPaths} / {@code publicMethods} da anotação (global ou método),
 *       a requisição é liberada sem validação de autorização.</li>
 *   <li><b>Anotação Global:</b> Se {@link EnableSecurity} estiver presente na classe principal/configuração
 *       da aplicação, a segurança é ativa para TODOS os endpoints não públicos.</li>
 *   <li><b>Anotação por Método:</b> Se {@link EnableSecurity} NÃO estiver na classe principal, apenas
 *       métodos ou controllers explicitamente anotados com {@link EnableSecurity} exigirão validação de autorização.
 *       Endpoints não anotados permanecem abertos.</li>
 *   <li><b>Auditoria:</b> Em caso de rejeição (falha no token ou falta de transação), é registrado log de auditoria
 *       via {@link SecurityAuditLogger} sem exposição de dados sensíveis.</li>
 * </ol>
 */
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
    private final ICacheRepository cacheRepository;

    private final SecurityMetadataResolver metadataResolver;
    private final SecurityAuditLogger auditLogger;

    @Autowired
    public AuthorizationInterceptor(
            ApplicationContext applicationContext,
            Environment environment,
            VaultParameter vaultParameter,
            TokenValidatorFactory tokenValidatorFactory,
            ICacheRepository cacheRepository,
            SecurityMetadataResolver metadataResolver,
            SecurityAuditLogger auditLogger) {
        this.applicationContext = applicationContext;
        this.tokenValidatorFactory = tokenValidatorFactory;
        this.cacheRepository = cacheRepository;
        this.metadataResolver = metadataResolver != null ? metadataResolver : new SecurityMetadataResolver();
        this.auditLogger = auditLogger != null ? auditLogger : new SecurityAuditLogger();
        this.enabledSecurity(environment, vaultParameter);
    }

    public AuthorizationInterceptor(
            ApplicationContext applicationContext,
            Environment environment,
            VaultParameter vaultParameter,
            TokenValidatorFactory tokenValidatorFactory,
            ICacheRepository cacheRepository) {
        this(applicationContext, environment, vaultParameter, tokenValidatorFactory, cacheRepository, null, null);
    }

    @Override
    public boolean preHandle(@NonNull HttpServletRequest request,
                             @NonNull HttpServletResponse response,
                             @NonNull Object handler) {

        this.request = request;

        // 1. Requisições OPTIONS (CORS) sempre permitidas
        if (isOptionsRequest(request)) {
            return true;
        }

        // 2. Resolver metadados das anotações global e local (@EnableSecurity)
        EnableSecurity globalSecurity = metadataResolver.getGlobalSecurityAnnotation(this.applicationContext);
        EnableSecurity localSecurity = metadataResolver.getLocalSecurityAnnotation(handler);

        // 3. Verificar se é uma requisição pública (pelo sistema, publicPaths ou publicMethods)
        if (metadataResolver.isPublicRequest(request, handler, globalSecurity, localSecurity)) {
            return true;
        }

        // 4. Determinar se a segurança está ativa para este endpoint
        boolean isSecurityActive = (globalSecurity != null) || (localSecurity != null);
        if (!isSecurityActive) {
            // Endpoint não possui anotação e segurança global não está ativa -> Permite acesso aberto
            return true;
        }

        // 5. Validar autorização do token e transactionid para endpoint protegido
        try {
            validateAuthorization(request.getHeader(AUTHORIZATION), request);
            validateTransactionId(request.getHeader(TRANSACTION_ID));
        } catch (Exception ex) {
            auditLogger.logUnauthorizedAttempt(request, ex.getMessage(), null);
            throw ex;
        }

        return true;
    }

    private void enabledSecurity(Environment environment, VaultParameter vaultParameter) {
        try {
            log.info("Ativando a Segurança");
            this.jwtService = new JwtSecurity(this.request, tokenValidatorFactory);
            log.info("Segurança ativada");
        } catch (Exception e) {
            log.error("Não foi possivel habilitar a segurança: {}", e.getMessage());
            throw new ApplicationException("Não foi possivel habilitar a segurança", e);
        }
    }

    private void validateAuthorization(String authorization, HttpServletRequest request) {
        if (StringUtils.isEmpty(authorization)) {
            log.error("Token não foi enviado");
            throw new AuthenticationException("The access token was not informed.");
        }

        jwtService.validateAuthorization(authorization, request);
    }

    private boolean isOptionsRequest(HttpServletRequest request) {
        return HttpMethod.OPTIONS.name().equals(request.getMethod());
    }

    public boolean isPublicUrl(String url) {
        EnableSecurity globalSecurity = metadataResolver.getGlobalSecurityAnnotation(this.applicationContext);
        return metadataResolver.isPublicUrl(url, globalSecurity);
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
}

