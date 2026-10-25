package com.br.azevedo.security.crypto;

/**
 * Contrato para serviços de criptografia simétrica (AES-256) e gerenciamento
 * de chaves mestres no ecossistema de segurança.
 */
public interface ICriptografiaService {

    /**
     * Criptografa o texto em claro utilizando a chave mestre obtida do AWS Parameter Store
     * (/app/data/security/cripto-{environment}) com o algoritmo AES-256-CBC.
     *
     * @param plainText texto em claro a ser criptografado
     * @return texto cifrado codificado em Base64 (contendo o IV)
     */
    String encrypt(String plainText);

    /**
     * Descriptografa o texto cifrado em Base64 utilizando a chave mestre obtida do AWS Parameter Store.
     *
     * @param encryptedText texto cifrado codificado em Base64
     * @return texto em claro original
     */
    String decrypt(String encryptedText);

    /**
     * Criptografa o texto em claro utilizando uma chave secreta específica fornecida.
     *
     * @param plainText texto em claro a ser criptografado
     * @param secretKey chave de criptografia customizada
     * @return texto cifrado codificado em Base64 (contendo o IV)
     */
    String encrypt(String plainText, String secretKey);

    /**
     * Descriptografa o texto cifrado em Base64 utilizando uma chave secreta específica fornecida.
     *
     * @param encryptedText texto cifrado codificado em Base64
     * @param secretKey chave de criptografia customizada
     * @return texto em claro original
     */
    String decrypt(String encryptedText, String secretKey);

    /**
     * Obtém a chave mestre resolvida a partir do AWS Parameter Store (ou cache Redis/local).
     *
     * @return chave mestre em texto
     */
    String getMasterKey();
}
