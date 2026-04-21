package com.br.azevedo.security.service.impl;

import com.br.azevedo.exception.AuthenticationException;
import com.br.azevedo.exception.AuthorizationException;
import com.br.azevedo.model.dto.UserDTO;
import com.br.azevedo.model.enums.PerfilEnum;
import com.br.azevedo.security.service.TokenValidationStrategy;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerMapping;

import java.util.*;

@Component
public class UserTokenValidationStrategy implements TokenValidationStrategy {
    private UserDTO user;

    @Override
    public void validate(HttpServletRequest request) {
        if (ObjectUtils.allNotNull(user, user.getId())) {
            if (ObjectUtils.isNotEmpty(request)) {

                @SuppressWarnings("unchecked")
                Map<String, String> pathVariables = (Map<String, String>) request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
                String email = pathVariables.get("email");

                if (StringUtils.isNotBlank(email) && email.equals(user.getEmail())) {
                    return;
                }

                Set<PerfilEnum> userPerfis = new HashSet<>(user.getPerfis());
                Set<PerfilEnum> requiredPerfis = EnumSet.of(PerfilEnum.ROLE_ADMIN, PerfilEnum.ROLE_APPLICATION);

                if (Collections.disjoint(userPerfis, requiredPerfis)) {
                    throw new AuthorizationException("Usuario não autorizado a acessar a informação.");
                }
            }

        } else {
            throw new AuthenticationException("The user is not valid.");
        }
    }

    @Override
    public boolean supports(Object token) {
        return token instanceof UserDTO;
    }

    @Override
    public void setObject(Object user) {
        this.user = (UserDTO) user;
    }
}
