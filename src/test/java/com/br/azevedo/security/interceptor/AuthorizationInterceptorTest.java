package com.br.azevedo.security.interceptor;

import com.br.azevedo.exception.AuthenticationException;
import com.br.azevedo.exception.AuthorizationException;
import com.br.azevedo.exception.NotFoundException;
import com.br.azevedo.infra.cache.redis.repository.ICacheRepository;
import com.br.azevedo.security.EnableSecurity;
import com.br.azevedo.security.audit.SecurityAuditLogger;
import com.br.azevedo.security.config.vault.VaultParameter;
import com.br.azevedo.security.service.TokenValidationStrategy;
import com.br.azevedo.security.strategy.TokenValidatorFactory;
import com.br.azevedo.security.utils.SecurityMetadataResolver;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.context.ApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.method.HandlerMethod;

import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class AuthorizationInterceptorTest {

    @Mock
    private ApplicationContext applicationContext;
    @Mock
    private Environment environment;
    @Mock
    private VaultParameter vaultParameter;
    @Mock
    private TokenValidatorFactory tokenValidatorFactory;
    @Mock
    private ICacheRepository cacheRepository;
    @Mock
    private SecurityAuditLogger auditLogger;
    @Mock
    private TokenValidationStrategy tokenStrategy;

    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;

    private SecurityMetadataResolver metadataResolver;
    private AuthorizationInterceptor interceptor;

    private static final String VALID_TX_ID = UUID.randomUUID().toString();
    private static final String VALID_BEARER_TOKEN = "Bearer valid.jwt.token";

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        initMessageUtils();
        metadataResolver = new SecurityMetadataResolver();

        interceptor = new AuthorizationInterceptor(
                applicationContext,
                environment,
                vaultParameter,
                tokenValidatorFactory,
                cacheRepository,
                metadataResolver,
                auditLogger
        );
    }

    private static void initMessageUtils() {
        try {
            Class<?> clazz = Class.forName("com.br.azevedo.utils.mensagemUtils.MessageUtils");
            java.lang.reflect.Field field = clazz.getDeclaredField("messageSource");
            field.setAccessible(true);
            if (field.get(null) == null) {
                org.springframework.context.MessageSource mockSource = mock(org.springframework.context.MessageSource.class);
                when(mockSource.getMessage(anyString(), any(), any())).thenAnswer(inv -> inv.getArgument(0));
                field.set(null, mockSource);
            }
        } catch (Exception ignored) {}
    }

    // Helper para simular HandlerMethod
    private HandlerMethod createHandlerMethod(Object controller, String methodName) throws NoSuchMethodException {
        return new HandlerMethod(controller, controller.getClass().getMethod(methodName));
    }

    @Test
    @DisplayName("Cenário 17 - Requisição OPTIONS (CORS pre-flight) deve ser sempre liberada")
    void shouldAllowOptionsRequest() {
        when(request.getMethod()).thenReturn("OPTIONS");
        assertTrue(interceptor.preHandle(request, response, new Object()));
        verifyNoInteractions(tokenValidatorFactory);
    }

    @Test
    @DisplayName("Cenário 5 e 16 - Endpoint público por isPublicUrl() deve permitir sem autorização ou transactionid")
    void shouldAllowPublicEndpointViaIsPublicUrl() {
        when(request.getMethod()).thenReturn("GET");
        when(request.getRequestURI()).thenReturn("/health");

        assertTrue(interceptor.preHandle(request, response, new Object()));
        verifyNoInteractions(tokenValidatorFactory);
    }

    @Test
    @DisplayName("Cenário 1 - Anotação Global: Endpoint protegido com token e transactionId válidos deve permitir")
    void globalSecurity_withValidTokenAndTxId_shouldAllow() {
        // Simular anotação global no ApplicationContext
        @EnableSecurity
        class MainApp {}

        when(applicationContext.getBeansWithAnnotation(EnableSecurity.class))
                .thenReturn(Map.of("mainApp", new MainApp()));

        when(request.getMethod()).thenReturn("GET");
        when(request.getRequestURI()).thenReturn("/api/usuarios");
        when(request.getHeader("Authorization")).thenReturn(VALID_BEARER_TOKEN);
        when(request.getHeader("transactionid")).thenReturn(VALID_TX_ID);
        when(tokenValidatorFactory.getStrategy(VALID_BEARER_TOKEN)).thenReturn(tokenStrategy);

        assertTrue(interceptor.preHandle(request, response, new Object()));
        verify(tokenStrategy).validate(request);
    }

    @Test
    @DisplayName("Cenário 2 e 11, 12 - Anotação Global: Endpoint protegido sem token deve rejeitar e gerar log")
    void globalSecurity_withoutToken_shouldRejectAndAudit() {
        @EnableSecurity
        class MainApp {}

        when(applicationContext.getBeansWithAnnotation(EnableSecurity.class))
                .thenReturn(Map.of("mainApp", new MainApp()));

        when(request.getMethod()).thenReturn("GET");
        when(request.getRequestURI()).thenReturn("/api/usuarios");
        when(request.getHeader("Authorization")).thenReturn(null);

        AuthenticationException ex = assertThrows(AuthenticationException.class, () ->
                interceptor.preHandle(request, response, new Object())
        );

        assertEquals("The access token was not informed.", ex.getMessage());
        verify(auditLogger).logUnauthorizedAttempt(eq(request), eq(ex.getMessage()), any());
    }

    @Test
    @DisplayName("Cenário 3 - Anotação Global: Token inválido deve rejeitar e gerar log")
    void globalSecurity_withInvalidToken_shouldRejectAndAudit() {
        @EnableSecurity
        class MainApp {}

        when(applicationContext.getBeansWithAnnotation(EnableSecurity.class))
                .thenReturn(Map.of("mainApp", new MainApp()));

        when(request.getMethod()).thenReturn("GET");
        when(request.getRequestURI()).thenReturn("/api/usuarios");
        when(request.getHeader("Authorization")).thenReturn("Bearer invalid.token");
        AuthenticationException invalidTokenEx = new AuthenticationException("Token is invalid or expired.");
        when(tokenValidatorFactory.getStrategy("Bearer invalid.token"))
                .thenThrow(invalidTokenEx);

        AuthenticationException ex = assertThrows(AuthenticationException.class, () ->
                interceptor.preHandle(request, response, new Object())
        );

        assertTrue(ex.getMessage().contains("Token is invalid"));
        verify(auditLogger).logUnauthorizedAttempt(eq(request), eq(ex.getMessage()), any());
    }

    @Test
    @DisplayName("Cenário 4 - Anotação Global: Token válido sem autorização de perfil deve rejeitar")
    void globalSecurity_withUnauthorizedToken_shouldReject() {
        @EnableSecurity
        class MainApp {}

        when(applicationContext.getBeansWithAnnotation(EnableSecurity.class))
                .thenReturn(Map.of("mainApp", new MainApp()));

        when(request.getMethod()).thenReturn("GET");
        when(request.getRequestURI()).thenReturn("/api/usuarios");
        when(request.getHeader("Authorization")).thenReturn(VALID_BEARER_TOKEN);
        when(tokenValidatorFactory.getStrategy(VALID_BEARER_TOKEN)).thenReturn(tokenStrategy);
        AuthorizationException unauthEx = new AuthorizationException("Usuario não autorizado.");
        doThrow(unauthEx).when(tokenStrategy).validate(request);

        AuthorizationException ex = assertThrows(AuthorizationException.class, () ->
                interceptor.preHandle(request, response, new Object())
        );

        assertEquals("Usuario não autorizado.", ex.getMessage());
        verify(auditLogger).logUnauthorizedAttempt(eq(request), eq(ex.getMessage()), any());
    }

    @Test
    @DisplayName("Sem TransactionID em endpoint protegido deve lançar NotFoundException e auditoria")
    void globalSecurity_withoutTransactionId_shouldReject() {
        @EnableSecurity
        class MainApp {}

        when(applicationContext.getBeansWithAnnotation(EnableSecurity.class))
                .thenReturn(Map.of("mainApp", new MainApp()));

        when(request.getMethod()).thenReturn("GET");
        when(request.getRequestURI()).thenReturn("/api/usuarios");
        when(request.getHeader("Authorization")).thenReturn(VALID_BEARER_TOKEN);
        when(request.getHeader("transactionid")).thenReturn(null);
        when(tokenValidatorFactory.getStrategy(VALID_BEARER_TOKEN)).thenReturn(tokenStrategy);

        NotFoundException ex = assertThrows(NotFoundException.class, () ->
                interceptor.preHandle(request, response, new Object())
        );

        assertEquals("The transactionid header is required.", ex.getMessage());
        verify(auditLogger).logUnauthorizedAttempt(eq(request), eq(ex.getMessage()), any());
    }

    @Test
    @DisplayName("Cenário 6 - Anotação Global com publicPaths deve liberar caminhos customizados")
    void globalSecurity_withPublicPaths_shouldAllowWithoutToken() {
        @EnableSecurity(publicPaths = {"/api/publico/.*"})
        class MainApp {}

        when(applicationContext.getBeansWithAnnotation(EnableSecurity.class))
                .thenReturn(Map.of("mainApp", new MainApp()));

        when(request.getMethod()).thenReturn("GET");
        when(request.getRequestURI()).thenReturn("/api/publico/relatorio");

        assertTrue(interceptor.preHandle(request, response, new Object()));
        verifyNoInteractions(tokenValidatorFactory);
    }

    @Test
    @DisplayName("Cenário 7 - Método com anotação deve validar autorização quando segurança global estiver inativa")
    void methodSecurity_annotatedMethod_shouldValidate() throws NoSuchMethodException {
        when(applicationContext.getBeansWithAnnotation(EnableSecurity.class)).thenReturn(Map.of());

        class TestController {
            @EnableSecurity
            public void protectedEndpoint() {}
        }

        TestController controller = new TestController();
        HandlerMethod handlerMethod = createHandlerMethod(controller, "protectedEndpoint");

        when(request.getMethod()).thenReturn("GET");
        when(request.getRequestURI()).thenReturn("/api/protegido");
        when(request.getHeader("Authorization")).thenReturn(VALID_BEARER_TOKEN);
        when(request.getHeader("transactionid")).thenReturn(VALID_TX_ID);
        when(tokenValidatorFactory.getStrategy(VALID_BEARER_TOKEN)).thenReturn(tokenStrategy);

        assertTrue(interceptor.preHandle(request, response, handlerMethod));
        verify(tokenStrategy).validate(request);
    }

    @Test
    @DisplayName("Cenário 8 e 9 - Método sem anotação deve permanecer aberto quando segurança global estiver inativa")
    void methodSecurity_unannotatedMethod_shouldRemainOpen() throws NoSuchMethodException {
        when(applicationContext.getBeansWithAnnotation(EnableSecurity.class)).thenReturn(Map.of());

        class TestController {
            @EnableSecurity
            public void protectedEndpoint() {}

            public void openEndpoint() {}
        }

        TestController controller = new TestController();
        HandlerMethod openHandlerMethod = createHandlerMethod(controller, "openEndpoint");

        when(request.getMethod()).thenReturn("GET");
        when(request.getRequestURI()).thenReturn("/api/aberto");

        // Deve permitir acesso sem token e sem transactionId
        assertTrue(interceptor.preHandle(request, response, openHandlerMethod));
        verifyNoInteractions(tokenValidatorFactory);
    }

    @Test
    @DisplayName("Cenário 10 - Método anotado com publicMethods não altera outros endpoints")
    void methodSecurity_withPublicMethods_shouldOnlyAffectAnnotatedMethod() throws NoSuchMethodException {
        when(applicationContext.getBeansWithAnnotation(EnableSecurity.class)).thenReturn(Map.of());

        class TestController {
            @EnableSecurity(publicMethods = {RequestMethod.GET})
            public void publicGetEndpoint() {}

            @EnableSecurity
            public void protectedEndpoint() {}
        }

        TestController controller = new TestController();
        HandlerMethod publicGetHandler = createHandlerMethod(controller, "publicGetEndpoint");
        HandlerMethod protectedHandler = createHandlerMethod(controller, "protectedEndpoint");

        // GET em publicGetEndpoint deve passar sem token
        when(request.getMethod()).thenReturn("GET");
        when(request.getRequestURI()).thenReturn("/api/public-get");
        assertTrue(interceptor.preHandle(request, response, publicGetHandler));

        // GET em protectedEndpoint deve exigir token
        when(request.getRequestURI()).thenReturn("/api/protected");
        when(request.getHeader("Authorization")).thenReturn(null);
        assertThrows(AuthenticationException.class, () ->
                interceptor.preHandle(request, response, protectedHandler)
        );
    }

    @Test
    @DisplayName("Cenário 15 - Método isPublicUrl() deve preservar contrato e funcionamentos das URLs padrão")
    void isPublicUrl_shouldPreserveContract() {
        assertTrue(interceptor.isPublicUrl("/health"));
        assertTrue(interceptor.isPublicUrl("/actuator"));
        assertTrue(interceptor.isPublicUrl("/swagger-ui.html"));
        assertFalse(interceptor.isPublicUrl("/api/privado"));
    }
}
