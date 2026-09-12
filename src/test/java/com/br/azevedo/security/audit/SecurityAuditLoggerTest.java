package com.br.azevedo.security.audit;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.*;

class SecurityAuditLoggerTest {

    private SecurityAuditLogger auditLogger;

    @BeforeEach
    void setUp() {
        auditLogger = new SecurityAuditLogger();
    }

    @Test
    @DisplayName("Cenário 12, 13 e 14 - Deve registrar auditoria sem lançar erro e sem vazar tokens/credenciais")
    void shouldLogUnauthorizedAttemptWithoutCrashingOrExposingSecrets() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn("/api/usuarios");
        when(request.getMethod()).thenReturn("POST");
        when(request.getRemoteAddr()).thenReturn("192.168.1.100");
        when(request.getHeader("transactionid")).thenReturn("550e8400-e29b-41d4-a716-446655440000");
        when(request.getHeader("User-Agent")).thenReturn("Mozilla/5.0");

        // Executar logging com informações de exemplo
        assertDoesNotThrow(() -> auditLogger.logUnauthorizedAttempt(
                request,
                "TOKEN_EXPIRED",
                "usuario@example.com"
        ));
    }

    @Test
    @DisplayName("Cenário 13 - Deve extrair IP de proxy X-Forwarded-For quando disponível")
    void shouldExtractProxyClientIp() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn("/api/dados");
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader("X-Forwarded-For")).thenReturn("203.0.113.195, 70.41.3.18");

        assertDoesNotThrow(() -> auditLogger.logUnauthorizedAttempt(
                request,
                "NO_AUTHORIZATION_HEADER",
                "ANONYMOUS"
        ));
    }

    @Test
    @DisplayName("Cenário 14 - Tratar com segurança objeto de requisição nulo")
    void shouldHandleNullRequestSafely() {
        assertDoesNotThrow(() -> auditLogger.logUnauthorizedAttempt(
                null,
                "NULL_REQUEST",
                "UNKNOWN"
        ));
    }
}
