package com.br.azevedo.security.crypto;

import com.br.azevedo.exception.ApplicationException;
import com.br.azevedo.infra.aws.ssm.AwsParameterStoreService;
import com.br.azevedo.security.crypto.config.CryptoProperties;
import com.br.azevedo.security.crypto.exception.CryptoException;
import com.br.azevedo.security.crypto.impl.CriptografiaServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.env.Environment;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CriptografiaServiceImplTest {

    @Mock
    private AwsParameterStoreService parameterStoreService;

    @Mock
    private Environment environment;

    private CriptografiaServiceImpl criptografiaService;

    private static final String MASTER_KEY = "my-super-secret-master-key-123456";
    private static final String PARAMETER_PATH = "/app/data/security/cripto-dev";

    @BeforeEach
    void setUp() {
        lenient().when(environment.getActiveProfiles()).thenReturn(new String[]{"dev"});
        CryptoProperties properties = new CryptoProperties();
        criptografiaService = new CriptografiaServiceImpl(parameterStoreService, environment, properties);
    }

    @Test
    @DisplayName("Deve criptografar e descriptografar com sucesso utilizando chave mestre do SSM")
    void shouldEncryptAndDecryptSuccessfully() {
        when(parameterStoreService.getParameter(eq(PARAMETER_PATH), eq(true), eq(Duration.ofDays(7))))
                .thenReturn(MASTER_KEY);

        String originalPassword = "MinhaSenhaSuperSecreta@2026!";
        String encrypted = criptografiaService.encrypt(originalPassword);

        assertNotNull(encrypted);
        assertNotEquals(originalPassword, encrypted);

        String decrypted = criptografiaService.decrypt(encrypted);
        assertEquals(originalPassword, decrypted);

        verify(parameterStoreService, times(2)).getParameter(PARAMETER_PATH, true, Duration.ofDays(7));
    }

    @Test
    @DisplayName("Deve descriptografar senha quando formato for iv:ciphertext")
    void shouldDecryptWhenFormatIsColonSeparated() {
        when(parameterStoreService.getParameter(eq(PARAMETER_PATH), eq(true), eq(Duration.ofDays(7))))
                .thenReturn(MASTER_KEY);

        String originalPassword = "OutraSenha123";
        String encrypted = criptografiaService.encrypt(originalPassword);

        byte[] combined = java.util.Base64.getDecoder().decode(encrypted);
        byte[] iv = java.util.Arrays.copyOfRange(combined, 0, 16);
        byte[] cipher = java.util.Arrays.copyOfRange(combined, 16, combined.length);
        String colonFormat = java.util.Base64.getEncoder().encodeToString(iv) + ":" + java.util.Base64.getEncoder().encodeToString(cipher);

        String decrypted = criptografiaService.decrypt(colonFormat);
        assertEquals(originalPassword, decrypted);
    }

    @Test
    @DisplayName("Deve extrair chave mestre quando formato no SSM for JSON")
    void shouldExtractMasterKeyWhenSsmValueIsJson() {
        String jsonSsm = "{\"key\":\"json-master-key-value\"}";
        when(parameterStoreService.getParameter(eq(PARAMETER_PATH), eq(true), eq(Duration.ofDays(7))))
                .thenReturn(jsonSsm);

        String original = "SenhaTesteJson";
        String encrypted = criptografiaService.encrypt(original);
        String decrypted = criptografiaService.decrypt(encrypted);

        assertEquals(original, decrypted);
    }

    @Test
    @DisplayName("Deve criptografar e descriptografar com chave customizada sem consultar o SSM")
    void shouldEncryptAndDecryptWithCustomKey() {
        String customKey = "custom-secret-key-987654321";
        String original = "SegredoEspecificoPorTenant";

        String encrypted = criptografiaService.encrypt(original, customKey);
        assertNotNull(encrypted);
        assertNotEquals(original, encrypted);

        String decrypted = criptografiaService.decrypt(encrypted, customKey);
        assertEquals(original, decrypted);
    }

    @Test
    @DisplayName("Deve retornar nulo ou em branco ao passar texto vazio")
    void shouldReturnBlankOnEmptyInput() {
        assertNull(criptografiaService.encrypt(null));
        assertEquals("", criptografiaService.encrypt(""));
        assertNull(criptografiaService.decrypt(null));
        assertEquals("", criptografiaService.decrypt(""));

        assertNull(criptografiaService.encrypt(null, "chave"));
        assertEquals("", criptografiaService.encrypt("", "chave"));
        assertNull(criptografiaService.decrypt(null, "chave"));
        assertEquals("", criptografiaService.decrypt("", "chave"));
    }

    @Test
    @DisplayName("Deve lançar ApplicationException quando chave mestre no SSM estiver vazia")
    void shouldThrowWhenMasterKeyIsEmpty() {
        when(parameterStoreService.getParameter(eq(PARAMETER_PATH), eq(true), eq(Duration.ofDays(7))))
                .thenReturn("");

        assertThrows(ApplicationException.class, () -> criptografiaService.encrypt("qualquer-coisa"));
    }

    @Test
    @DisplayName("Deve lançar CryptoException ao informar chave customizada nula ou vazia")
    void shouldThrowWhenCustomKeyIsBlank() {
        assertThrows(CryptoException.class, () -> criptografiaService.encrypt("texto", null));
        assertThrows(CryptoException.class, () -> criptografiaService.encrypt("texto", " "));
        assertThrows(CryptoException.class, () -> criptografiaService.decrypt("texto", null));
        assertThrows(CryptoException.class, () -> criptografiaService.decrypt("texto", " "));
    }

    @Test
    @DisplayName("Deve lançar CryptoException ao falhar na descriptografia de texto inválido")
    void shouldThrowCryptoExceptionOnInvalidEncryptedText() {
        when(parameterStoreService.getParameter(eq(PARAMETER_PATH), eq(true), eq(Duration.ofDays(7))))
                .thenReturn(MASTER_KEY);

        assertThrows(CryptoException.class, () -> criptografiaService.decrypt("texto-invalido-curto"));
    }
}
