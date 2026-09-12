package com.br.azevedo.security.audit;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;

import static com.br.azevedo.security.utils.Constantes.TRANSACTION_ID;

/**
 * Componente responsável pelo registro seguro de auditoria de segurança para tentativas
 * de acesso não autorizadas ou falhas de autenticação.
 *
 * <p><b>Princípios de Segurança dos Logs:</b></p>
 * <ul>
 *   <li>Nunca registra tokens JWT completos, access/refresh tokens, senhas ou credenciais.</li>
 *   <li>Registra apenas metadados públicos e não sensíveis da requisição HTTP (IP, URI, método, transactionId, etc.).</li>
 * </ul>
 */
@Slf4j
@Component
public class SecurityAuditLogger {

    private static final String UNKNOWN = "UNKNOWN";
    private static final String HEADER_X_FORWARDED_FOR = "X-Forwarded-For";
    private static final String HEADER_USER_AGENT = "User-Agent";
    private static final String HEADER_X_REQUEST_ID = "X-Request-ID";

    /**
     * Registra em log de auditoria uma tentativa de acesso não autorizada.
     *
     * @param request a requisição HTTP interceptada.
     * @param reason o motivo da rejeição da autorização.
     * @param userIdentifier identificador não sensível do usuário (ex: e-mail, clientId, ou ANONYMOUS).
     */
    public void logUnauthorizedAttempt(HttpServletRequest request, String reason, String userIdentifier) {
        if (request == null) {
            log.warn("UNAUTHORIZED_REQUEST reason={} user={}", sanitize(reason), sanitize(userIdentifier));
            return;
        }

        String clientIp = extractClientIp(request);
        String httpMethod = request.getMethod();
        String uri = request.getRequestURI();
        String transactionId = extractTransactionId(request);
        String userAgent = request.getHeader(HEADER_USER_AGENT);
        String resolvedUser = StringUtils.defaultIfBlank(userIdentifier, "ANONYMOUS");

        log.warn("UNAUTHORIZED_REQUEST result=REJECTED user={} ip={} method={} uri={} transactionId={} userAgent={} reason={}",
                sanitize(resolvedUser),
                sanitize(clientIp),
                sanitize(httpMethod),
                sanitize(uri),
                sanitize(transactionId),
                sanitize(userAgent),
                sanitize(reason));
    }

    /**
     * Extrai o IP de origem da requisição, considerando cabeçalhos de proxy/load balancer se presentes.
     */
    private String extractClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader(HEADER_X_FORWARDED_FOR);
        if (StringUtils.isNotBlank(xForwardedFor) && !UNKNOWN.equalsIgnoreCase(xForwardedFor)) {
            return xForwardedFor.split(",")[0].trim();
        }
        return StringUtils.defaultIfBlank(request.getRemoteAddr(), UNKNOWN);
    }

    /**
     * Extrai o identificador de transação da requisição.
     */
    private String extractTransactionId(HttpServletRequest request) {
        String txId = request.getHeader(TRANSACTION_ID);
        if (StringUtils.isBlank(txId)) {
            txId = request.getHeader(HEADER_X_REQUEST_ID);
        }
        return StringUtils.defaultIfBlank(txId, UNKNOWN);
    }

    /**
     * Higieniza os valores dos logs substituindo nulos por UNKNOWN e removendo quebras de linha.
     */
    private String sanitize(String value) {
        if (StringUtils.isBlank(value)) {
            return UNKNOWN;
        }
        return value.replaceAll("[\r\n]", "_");
    }
}
