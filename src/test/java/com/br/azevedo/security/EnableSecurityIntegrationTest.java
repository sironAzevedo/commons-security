package com.br.azevedo.security;

import com.br.azevedo.infra.cache.redis.repository.ICacheRepository;
import com.br.azevedo.security.audit.SecurityAuditLogger;
import com.br.azevedo.security.config.vault.VaultParameter;
import com.br.azevedo.security.interceptor.AuthorizationInterceptor;
import com.br.azevedo.security.interceptor.SecurityConfig;
import com.br.azevedo.security.service.TokenValidationStrategy;
import com.br.azevedo.security.strategy.TokenValidatorFactory;
import com.br.azevedo.security.utils.SecurityMetadataResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest
@Import({
        EnableSecurityIntegrationTest.TestSampleController.class,
        SecurityConfig.class,
        AuthorizationInterceptor.class,
        SecurityMetadataResolver.class,
        SecurityAuditLogger.class
})
@TestPropertySource(properties = "security.enabled=true")
class EnableSecurityIntegrationTest {

    @SpringBootApplication
    static class TestApplication {}

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private TokenValidatorFactory tokenValidatorFactory;

    @MockBean
    private VaultParameter vaultParameter;

    @MockBean
    private ICacheRepository cacheRepository;

    @MockBean
    private TokenValidationStrategy tokenValidationStrategy;

    private static final String TX_ID = UUID.randomUUID().toString();

    @RestController
    @RequestMapping("/test")
    public static class TestSampleController {

        @GetMapping("/open")
        public ResponseEntity<String> openEndpoint() {
            return ResponseEntity.ok("OPEN");
        }

        @EnableSecurity
        @GetMapping("/secured")
        public ResponseEntity<String> securedEndpoint() {
            return ResponseEntity.ok("SECURED");
        }

        @EnableSecurity(publicPaths = {"/test/public-subpath"})
        @GetMapping("/public-subpath")
        public ResponseEntity<String> publicSubpath() {
            return ResponseEntity.ok("PUBLIC_SUBPATH");
        }
    }

    @BeforeEach
    void setUp() {
        initMessageUtils();
        when(tokenValidatorFactory.getStrategy(anyString())).thenReturn(tokenValidationStrategy);
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

    @Test
    @DisplayName("Endpoint sem anotação deve permanecer aberto quando segurança global estiver inativa")
    void openEndpoint_shouldBeAccessibleWithoutToken() throws Exception {
        mockMvc.perform(get("/test/open"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Endpoint anotado com @EnableSecurity deve exigir token e transactionid")
    void securedEndpoint_withoutToken_shouldFail() {
        org.junit.jupiter.api.Assertions.assertThrows(Exception.class, () ->
                mockMvc.perform(get("/test/secured"))
        );
    }

    @Test
    @DisplayName("Endpoint anotado com @EnableSecurity com token e transactionid válidos deve funcionar")
    void securedEndpoint_withToken_shouldSucceed() throws Exception {
        mockMvc.perform(get("/test/secured")
                        .header("Authorization", "Bearer valid_token")
                        .header("transactionid", TX_ID))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Endpoint anotado com publicPaths deve ser acessível sem token")
    void publicSubpathEndpoint_shouldBeAccessibleWithoutToken() throws Exception {
        mockMvc.perform(get("/test/public-subpath"))
                .andExpect(status().isOk());
    }
}
