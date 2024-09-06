package com.br.azevedo.security.user;

import com.br.azevedo.exception.AuthorizationException;
import com.br.azevedo.model.enums.PerfilEnum;
import com.br.azevedo.security.models.jwt.JwtEntity;
import com.br.azevedo.security.secretManager.VaultSecretManager;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerMapping;

import java.util.*;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Slf4j
@Aspect
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(
        value = {"security.enabled"},
        havingValue = "true",
        matchIfMissing = true
)
public class UserValidation {

    private final HttpServletRequest request;
    private final VaultSecretManager vaultSecretManager;

    @Pointcut("@annotation(validationUser)")
    public void callAt(ValidationUser validationUser) {}

    @Before("callAt(validationUser)")
    public void checkAccess(ValidationUser validationUser) {
        var token = request.getHeader(AUTHORIZATION);
        var apiSecret = vaultSecretManager.getSecret("auth").get("API_SECRET").toString();
        var user = JwtEntity.getUser(token, apiSecret);

        @SuppressWarnings("unchecked")
        Map<String, String> pathVariables = (Map<String, String>) request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
        String email = pathVariables.get("email");

        if (email.equals(user.getEmail())) {
            return;
        }

        Set<PerfilEnum> userPerfis = new HashSet<>(user.getPerfis());
        Set<PerfilEnum> requiredPerfis = EnumSet.of(PerfilEnum.ROLE_ADMIN, PerfilEnum.ROLE_APPLICATION);

        for (PerfilEnum perfil: requiredPerfis) {
            if (userPerfis.contains(perfil)) {
                return;
            }
        }

        log.error("Usuario não autorizado a acessar a informação");
        throw new AuthorizationException("Usuario não autorizado a acessar a informação.");
    }
}
