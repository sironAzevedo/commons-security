package com.br.azevedo.security.service;

import jakarta.servlet.http.HttpServletRequest;

public interface TokenValidationStrategy {
    void validate(HttpServletRequest request, Object token);
    boolean supports(Object token);
}
