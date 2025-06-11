package com.br.azevedo.security.service.impl;

import com.br.azevedo.exception.AuthenticationException;
import com.br.azevedo.exception.AuthorizationException;
import com.br.azevedo.model.enums.PerfilEnum;
import com.br.azevedo.security.models.jwt.AppEntity;
import com.br.azevedo.security.service.TokenValidationStrategy;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class AppTokenValidationStrategy implements TokenValidationStrategy {

    @Value("${security.scopes:#{null}}")
    private String scopes;

    @Override
    public void validate(HttpServletRequest request, Object token) {
        AppEntity app = (AppEntity) token;
        if (ObjectUtils.isEmpty(app)) {
            throw new AuthenticationException("App token inválido.");
        }

        if (StringUtils.isBlank(app.getClientId())) {
            throw new AuthenticationException("The user is not valid.");
        }

        if (CollectionUtils.isEmpty(app.getPerfis())) {
            throw new AuthorizationException("Perfis obrigatórios não informados.");
        }

        if (StringUtils.isBlank(app.getScopes())) {
            throw new AuthorizationException("Scopes obrigatórios não informados.");
        }

        // Validar SCOPES
        if (StringUtils.isNotBlank(this.scopes)) {
            Set<String> scopesApp = Stream.of(this.scopes.split(",")).map(String::trim).collect(Collectors.toSet());
            Set<String> scopesToken = Stream.of(app.getScopes().split(",")).map(String::trim).collect(Collectors.toSet());

            if (Collections.disjoint(scopesApp, scopesToken)) {
                throw new AuthorizationException("App não autorizado: escopos inválidos.");
            }
        }

        // Validar PERFIS
        Set<PerfilEnum> requiredPerfis = EnumSet.of(PerfilEnum.ROLE_APPLICATION);
        if (!requiredPerfis.containsAll(app.getPerfis())) {
            throw new AuthorizationException("App não autorizado: perfil necessário ausente.");
        }

        String url = app.getOrigen();
        String regexDev = ".*/realms/myrealm(/.*)?$";
        String regexHubServices = ".*/realms/managementHubServices(/.*)?$";

        boolean isDev = url.matches(regexDev);
        boolean isHubServices = url.matches(regexHubServices);
        if (!isDev && !isHubServices) {
            throw new AuthenticationException("origen do token inválido. Entre em contato com o administrador.");
        }
    }

    @Override
    public boolean supports(Object token) {
        return token instanceof AppEntity;
    }
}
