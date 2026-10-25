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
}
