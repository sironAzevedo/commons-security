package com.br.azevedo.security.crypto.impl;

import com.br.azevedo.exception.ApplicationException;
import com.br.azevedo.infra.aws.ssm.AwsParameterStoreService;
import com.br.azevedo.security.crypto.ICryptoService;
import com.br.azevedo.security.crypto.config.CryptoProperties;
import com.br.azevedo.security.crypto.exception.CryptoException;
import com.br.azevedo.utils.EnvironmentUtils;
import com.br.azevedo.utils.JsonUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.core.env.Environment;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Implementação do serviço de criptografia simétrica AES-256-CBC gerenciada
 * com chave mestre armazenada no AWS Parameter Store e cacheada automaticamente.
 */
@Slf4j
public class CriptografiaServiceImpl implements ICryptoService {

    private final AwsParameterStoreService parameterStoreService;
    private final Environment environment;
    private final CryptoProperties cryptoProperties;

    public CriptografiaServiceImpl(AwsParameterStoreService parameterStoreService, Environment environment) {
        this(parameterStoreService, environment, new CryptoProperties());
    }

    public CriptografiaServiceImpl(
            AwsParameterStoreService parameterStoreService,
            Environment environment,
            CryptoProperties cryptoProperties) {
        this.parameterStoreService = parameterStoreService;
        this.environment = environment;
        this.cryptoProperties = cryptoProperties != null ? cryptoProperties : new CryptoProperties();
    }

    @Override
    public String encrypt(String plainText) {
        if (StringUtils.isBlank(plainText)) {
            return plainText;
        }
        String masterKey = getMasterKey();
        return encrypt(plainText, masterKey);
    }

    @Override
    public String decrypt(String encryptedText) {
        if (StringUtils.isBlank(encryptedText)) {
            return encryptedText;
        }
        String masterKey = getMasterKey();
        return decrypt(encryptedText, masterKey);
    }

    @Override
    public String encrypt(String plainText, String secretKey) {
        if (StringUtils.isBlank(plainText)) {
            return plainText;
        }
        if (StringUtils.isBlank(secretKey)) {
            throw new CryptoException("A chave para criptografia não pode ser nula ou vazia");
        }

        try {
            byte[] keyBytes = deriveKey(secretKey);
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");

            byte[] iv = new byte[cryptoProperties.getIvLengthBytes()];
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance(cryptoProperties.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            byte[] combined = new byte[iv.length + encryptedBytes.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);

            return Base64.getEncoder().encodeToString(combined);
        } catch (CryptoException ce) {
            throw ce;
        } catch (Exception e) {
            log.error("Erro ao criptografar texto: {}", e.getMessage());
            throw new CryptoException("Erro ao criptografar texto: " + e.getMessage(), e);
        }
    }

    @Override
    public String decrypt(String encryptedText, String secretKey) {
        if (StringUtils.isBlank(encryptedText)) {
            return encryptedText;
        }
        if (StringUtils.isBlank(secretKey)) {
            throw new CryptoException("A chave para descriptografia não pode ser nula ou vazia");
        }

        try {
            byte[] keyBytes = deriveKey(secretKey);
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");

            byte[] iv;
            byte[] cipherBytes;

            if (encryptedText.contains(":")) {
                String[] parts = encryptedText.split(":", 2);
                iv = Base64.getDecoder().decode(parts[0]);
                cipherBytes = Base64.getDecoder().decode(parts[1]);
            } else {
                byte[] combined = Base64.getDecoder().decode(encryptedText);
                int ivLength = cryptoProperties.getIvLengthBytes();
                if (combined.length <= ivLength) {
                    throw new IllegalArgumentException("Texto criptografado inválido ou corrompido");
                }
                iv = Arrays.copyOfRange(combined, 0, ivLength);
                cipherBytes = Arrays.copyOfRange(combined, ivLength, combined.length);
            }

            Cipher cipher = Cipher.getInstance(cryptoProperties.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));

            byte[] decryptedBytes = cipher.doFinal(cipherBytes);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (CryptoException ce) {
            throw ce;
        } catch (Exception e) {
            log.error("Erro ao descriptografar texto: {}", e.getMessage());
            throw new CryptoException("Erro ao descriptografar texto: " + e.getMessage(), e);
        }
    }

    @Override
    public String getMasterKey() {
        String activeEnv = EnvironmentUtils.resolveActiveEnvironment(environment);
        String parameterPath = String.format(cryptoProperties.getParameterPathPattern(), activeEnv);

        log.debug("Buscando chave mestre no SSM Parameter Store: [{}] com TTL de {}", parameterPath, cryptoProperties.getCacheTtl());
        try {
            String rawValue = parameterStoreService.getParameter(parameterPath, true, cryptoProperties.getCacheTtl());
            return extractKey(rawValue, parameterPath);
        } catch (Exception e) {
            log.error("Erro ao obter chave mestre do Parameter Store no caminho [{}]: {}", parameterPath, e.getMessage());
            throw new ApplicationException(String.format("Erro ao obter chave mestre no Parameter Store (%s): %s", parameterPath, e.getMessage()), e);
        }
    }

    private byte[] deriveKey(String masterKey) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        return sha.digest(masterKey.getBytes(StandardCharsets.UTF_8));
    }

    private String extractKey(String rawValue, String parameterPath) {
        if (StringUtils.isBlank(rawValue)) {
            throw new ApplicationException(String.format("Chave mestre no Parameter Store (%s) está vazia", parameterPath));
        }

        String trimmed = rawValue.trim();
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            try {
                Map<String, Object> map = JsonUtils.jsonToObject(trimmed, Map.class);
                for (String keyName : List.of("key", "master_key", "chave", "chave_mestre", "value", "password")) {
                    if (map.containsKey(keyName) && map.get(keyName) != null) {
                        return map.get(keyName).toString();
                    }
                }
            } catch (Exception e) {
                log.warn("Falha ao analisar JSON do parâmetro [{}]. Utilizando valor como texto puro.", parameterPath);
            }
        }

        return trimmed;
    }
}
