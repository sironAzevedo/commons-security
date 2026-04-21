package com.br.azevedo.security.service;

import jakarta.servlet.http.HttpServletRequest;

public interface TokenValidationStrategy {
    void validate(HttpServletRequest request);

    boolean supports(Object token);

    void setObject(Object user);
}
