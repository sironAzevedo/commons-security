package com.br.azevedo.security.crypto.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Propriedades de configuração para o módulo de criptografia.
 * Podem ser customizadas no application.yml através do prefixo 'security.crypto'.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "security.crypto")
public class CryptoProperties {

    /**
     * Padrão de caminho no AWS SSM Parameter Store para localização da chave mestre.
     * O placeholder '%s' será preenchido com o ambiente ativo (ex: dev, prd).
     */
    private String parameterPathPattern = "/app/data/security/cripto-%s";

    /**
     * Tempo de expiração (TTL) do cache para a chave mestre (padrão: 7 dias).
     */
    private Duration cacheTtl = Duration.ofDays(7);

    /**
     * Algoritmo de cifra utilizado (padrão: AES/CBC/PKCS5Padding).
     */
    private String algorithm = "AES/CBC/PKCS5Padding";

    /**
     * Tamanho em bytes do vetor de inicialização (IV) (padrão: 16 bytes).
     */
    private int ivLengthBytes = 16;
}
