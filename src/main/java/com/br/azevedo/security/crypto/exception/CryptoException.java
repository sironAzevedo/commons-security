package com.br.azevedo.security.crypto.exception;

import com.br.azevedo.exception.ApplicationException;

/**
 * Exceção lançada em caso de falha nas operações de criptografia e descriptografia.
 */
public class CryptoException extends ApplicationException {

    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
