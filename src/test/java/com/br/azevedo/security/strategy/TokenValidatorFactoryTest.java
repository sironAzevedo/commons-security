package com.br.azevedo.security.strategy;

import com.br.azevedo.infra.aws.ssm.AwsParameterStoreService;
import com.br.azevedo.infra.cache.redis.repository.ICacheRepository;
import com.br.azevedo.model.dto.UserDTO;
import com.br.azevedo.security.service.TokenValidationStrategy;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.env.MockEnvironment;

import com.br.azevedo.security.secretManager.VaultSecretManager;
import org.springframework.beans.factory.ObjectProvider;

import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TokenValidatorFactoryTest {

    @Mock
    private AwsParameterStoreService parameterStoreService;

    @Mock
    private ICacheRepository cacheRepository;

    @Mock
    private TokenValidationStrategy strategy;

    @Mock
    private ObjectProvider<VaultSecretManager> vaultSecretManagerProvider;

    @Mock
    private VaultSecretManager vaultSecretManager;

    private MockEnvironment environment;
    private TokenValidatorFactory factory;

    private static final String TEST_SECRET = "super-secret-key-that-is-at-least-256-bits-long-for-hmac-sha!";

    @BeforeEach
    void setUp() {
        environment = new MockEnvironment();
        factory = new TokenValidatorFactory(List.of(strategy), parameterStoreService, environment, cacheRepository);
    }

    @Test
    @DisplayName("Deve resolver ambiente como 'dev' quando nenhum profile for informado")
    void shouldResolveDevWhenNoProfile() {
        String env = factory.resolveActiveEnvironment();
        assertEquals("dev", env);
    }

    @Test
    @DisplayName("Deve resolver ambiente a partir de spring.profiles.active")
    void shouldResolveEnvironmentFromActiveProfile() {
        environment.setProperty("spring.profiles.active", "prod,swagger");
        String env = factory.resolveActiveEnvironment();
        assertEquals("prod", env);
    }

    @Test
    @DisplayName("Deve buscar secret no Parameter Store com fallback para 'dev'")
    void shouldGetSecretFromParameterStoreWithDevFallback() {
        when(parameterStoreService.getParameter("/auth-api/jwt/credentials-dev", true))
                .thenReturn("{\"API_SECRET\":\"" + TEST_SECRET + "\"}");

        String apiSecret = factory.getApiSecret();
        assertEquals(TEST_SECRET, apiSecret);
        verify(parameterStoreService).getParameter("/auth-api/jwt/credentials-dev", true);
    }

    @Test
    @DisplayName("Deve aceitar secret como texto puro no Parameter Store")
    void shouldAcceptPlainTextSecretFromParameterStore() {
        environment.setProperty("spring.profiles.active", "homolog");
        when(parameterStoreService.getParameter("/auth-api/jwt/credentials-homolog", true))
                .thenReturn(TEST_SECRET);

        String apiSecret = factory.getApiSecret();
        assertEquals(TEST_SECRET, apiSecret);
    }

    @Test
    @DisplayName("Deve retornar secret do cache se presente")
    void shouldReturnSecretFromCacheWhenPresent() {
        when(cacheRepository.getCacheByNameAndKey("security_jwt_credentials", "/auth-api/jwt/credentials-dev", String.class))
                .thenReturn(TEST_SECRET);

        String apiSecret = factory.getApiSecret();
        assertEquals(TEST_SECRET, apiSecret);
    }

    @Test
    @DisplayName("Deve selecionar a strategy correta ao validar o token")
    void shouldSelectSupportedStrategy() {
        when(parameterStoreService.getParameter("/auth-api/jwt/credentials-dev", true))
                .thenReturn(TEST_SECRET);
        when(strategy.supports(any())).thenReturn(true);

        String token = Jwts.builder()
                .claim("type", "USER")
                .claim("authUser", Map.of("nome", "Joao", "email", "joao@example.com"))
                .setExpiration(new Date(System.currentTimeMillis() + 60000))
                .signWith(Keys.hmacShaKeyFor(TEST_SECRET.getBytes()))
                .compact();

        TokenValidationStrategy result = factory.getStrategy("Bearer " + token);
        assertNotNull(result);
        assertEquals(strategy, result);
        verify(strategy).setObject(any(UserDTO.class));
    }

    @Test
    @DisplayName("Deve utilizar secret direto configurado via security.jwt.secret sem chamar o SSM")
    void shouldUseDirectJwtSecretFromProperty() {
        environment.setProperty("security.jwt.secret", "minha-chave-direta");
        String secret = factory.getApiSecret();
        assertEquals("minha-chave-direta", secret);
    }

    @Test
    @DisplayName("Deve utilizar caminho customizado de SSM configurado via security.jwt.ssm-path")
    void shouldUseCustomSsmPath() {
        environment.setProperty("security.jwt.ssm-path", "/custom/auth/jwt-key");
        when(parameterStoreService.getParameter("/custom/auth/jwt-key", true))
                .thenReturn(TEST_SECRET);

        String secret = factory.getApiSecret();
        assertEquals(TEST_SECRET, secret);
        verify(parameterStoreService).getParameter("/custom/auth/jwt-key", true);
    }

    @Test
    @DisplayName("Deve lançar exceção explicativa quando ocorrer erro de IAM no SSM")
    void shouldThrowHelpfulExceptionWhenIamAccessDenied() {
        when(parameterStoreService.getParameter("/auth-api/jwt/credentials-dev", true))
                .thenThrow(new com.br.azevedo.exception.ApplicationException(
                        "User: arn:aws:iam::123:user/test is not authorized to perform: ssm:GetParameter on resource: arn:aws:ssm:sa-east-1:123:parameter/auth-api/jwt/credentials-dev"
                ));

        com.br.azevedo.exception.ApplicationException ex = org.junit.jupiter.api.Assertions.assertThrows(
                com.br.azevedo.exception.ApplicationException.class,
                () -> factory.getApiSecret()
        );

        org.junit.jupiter.api.Assertions.assertTrue(ex.getMessage().contains("permissão IAM 'ssm:GetParameter'"));
        org.junit.jupiter.api.Assertions.assertTrue(ex.getMessage().contains("security.jwt.secret"));
    }

    @Test
    @DisplayName("Deve extrair secret do formato gerado pelo ManagerKeyclockService (clientId + clientSecret)")
    void shouldExtractSecretFromManagerKeycloakFormat() {
        when(parameterStoreService.getParameter("/auth-api/jwt/credentials-dev", true))
                .thenReturn("{\"clientId\":\"app-uuid-1234\",\"clientSecret\":\"" + TEST_SECRET + "\"}");

        String apiSecret = factory.getApiSecret();
        assertEquals(TEST_SECRET, apiSecret);
    }

    @Test
    @DisplayName("Deve extrair secret do formato OAuth2 padrão (client_id + client_secret)")
    void shouldExtractSecretFromOAuth2SnakeCaseFormat() {
        when(parameterStoreService.getParameter("/auth-api/jwt/credentials-dev", true))
                .thenReturn("{\"client_id\":\"app-uuid\",\"client_secret\":\"" + TEST_SECRET + "\"}");

        String apiSecret = factory.getApiSecret();
        assertEquals(TEST_SECRET, apiSecret);
    }

    @Test
    @DisplayName("Deve extrair secret do formato com chave 'value'")
    void shouldExtractSecretFromValueKey() {
        when(parameterStoreService.getParameter("/auth-api/jwt/credentials-dev", true))
                .thenReturn("{\"value\":\"" + TEST_SECRET + "\"}");

        String apiSecret = factory.getApiSecret();
        assertEquals(TEST_SECRET, apiSecret);
    }

    @Test
    @DisplayName("Deve extrair secret do formato com chave 'jwtSecret' ou 'JWT_SECRET'")
    void shouldExtractSecretFromJwtSecretKey() {
        when(parameterStoreService.getParameter("/auth-api/jwt/credentials-dev", true))
                .thenReturn("{\"jwtSecret\":\"" + TEST_SECRET + "\"}");

        String apiSecret = factory.getApiSecret();
        assertEquals(TEST_SECRET, apiSecret);
    }

    @Test
    @DisplayName("Deve extrair secret quando houver apenas um campo customizado no JSON")
    void shouldExtractSecretFromSingleFieldJson() {
        when(parameterStoreService.getParameter("/auth-api/jwt/credentials-dev", true))
                .thenReturn("{\"minha_chave_customizada\":\"" + TEST_SECRET + "\"}");

        String apiSecret = factory.getApiSecret();
        assertEquals(TEST_SECRET, apiSecret);
    }

    @Test
    @DisplayName("Deve fazer trim em secret com espaços no JSON")
    void shouldTrimSecretFromJsonObject() {
        when(parameterStoreService.getParameter("/auth-api/jwt/credentials-dev", true))
                .thenReturn("{\"secret\":\"  " + TEST_SECRET + "  \\n\"}");

        String apiSecret = factory.getApiSecret();
        assertEquals(TEST_SECRET, apiSecret);
    }

    @Test
    @DisplayName("Deve lançar exceção quando o JSON contiver clientId mas nenhuma secret reconhecida")
    void shouldThrowExceptionWhenJsonHasClientIdWithoutSecret() {
        when(parameterStoreService.getParameter("/auth-api/jwt/credentials-dev", true))
                .thenReturn("{\"clientId\":\"app-123\",\"descricao\":\"apenas app sem secret\"}");

        com.br.azevedo.exception.ApplicationException ex = org.junit.jupiter.api.Assertions.assertThrows(
                com.br.azevedo.exception.ApplicationException.class,
                () -> factory.getApiSecret()
        );

        org.junit.jupiter.api.Assertions.assertTrue(ex.getMessage().contains("Credenciais incompletas no Parameter Store"));
    }

    @Test
    @DisplayName("Deve recorrer ao fallback do Vault quando SSM falhar")
    void shouldFallbackToVaultWhenSsmFails() {
        TokenValidatorFactory factoryWithVault = new TokenValidatorFactory(
                List.of(strategy), parameterStoreService, environment, cacheRepository, vaultSecretManagerProvider);

        when(parameterStoreService.getParameter("/auth-api/jwt/credentials-dev", true))
                .thenThrow(new RuntimeException("SSM indisponível"));
        when(vaultSecretManagerProvider.getIfAvailable()).thenReturn(vaultSecretManager);
        when(vaultSecretManager.getSecret("auth")).thenReturn(Map.of("API_SECRET", TEST_SECRET));

        String secret = factoryWithVault.getApiSecret();
        assertEquals(TEST_SECRET, secret);
        verify(cacheRepository).saveCacheByNameAndKey("security_jwt_credentials", "/auth-api/jwt/credentials-dev", TEST_SECRET, Duration.ofHours(1));
    }
}
