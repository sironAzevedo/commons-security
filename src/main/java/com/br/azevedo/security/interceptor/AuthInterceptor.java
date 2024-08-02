package com.br.azevedo.security.interceptor;

import com.br.azevedo.exception.AuthenticationException;
import com.br.azevedo.exception.ValidationException;
import com.br.azevedo.security.JwtSecurity;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Set;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthInterceptor implements HandlerInterceptor {

    private static final String AUTHORIZATION = "Authorization";
    private static final String TRANSACTION_ID = "transactionid";

    private final JwtSecurity jwtService;
    private final Set<String> publicPaths;

    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) {

        log.info("Verificando se o path [{}] é publica", request.getRequestURI());
        if (isOptionsRequest(request) || isPublicUrl(request.getRequestURI())) {
            log.info("O path [{}] é publica", request.getRequestURI());
            return true;
        }

//        validateTransactionId(request.getHeader(TRANSACTION_ID));

        log.info("Validando o token");
        validateAuthorization(request.getHeader(AUTHORIZATION));
        log.info("Token valido");

        request.setAttribute("serviceid", generateServiceId());
        return true;
    }

    private boolean isPublicUrl(String url) {
        return publicPaths.stream().anyMatch(url::contains);
    }

    private boolean isOptionsRequest(HttpServletRequest request) {
        return HttpMethod.OPTIONS.name().equals(request.getMethod());
    }

    private void validateTransactionId(String transactionId) {
        if (isEmpty(transactionId)) {
            throw new ValidationException("The transactionid header is required.");
        }
    }

    private void validateAuthorization(String authorization) {
        if (isEmpty(authorization)) {
            log.error("Token não foi enviado");
            throw new AuthenticationException("The access token was not informed.");
        }
        jwtService.validateAuthorization(authorization);
    }

    private boolean isEmpty(String value) {
        return value == null || value.trim().isEmpty();
    }

    private String generateServiceId() {
        return UUID.randomUUID().toString();
    }
}
