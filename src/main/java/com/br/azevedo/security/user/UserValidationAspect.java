package com.br.azevedo.security.user;

import com.br.azevedo.exception.AuthorizationException;
import com.br.azevedo.model.enums.PerfilEnum;
import com.br.azevedo.security.models.jwt.JwtEntity;
import com.br.azevedo.security.secretMnager.VaultSecretsManager;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.web.servlet.HandlerMapping;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;

@Slf4j
@Aspect
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(
        value = {"security.enabled"},
        havingValue = "true",
        matchIfMissing = true
)
public class UserValidationAspect {

//    @Value("${app-config.secrets.api-secret}")
//    private String apiSecret;

    private static final String AUTHORIZATION = "Authorization";
    private final HttpServletRequest request;


    @Pointcut("@annotation(validationUser)")
    public void callAt(ValidationUser validationUser) {}

    @Before("callAt(validationUser)")
    public void logMethodCall(ValidationUser validationUser) {
        log.info("Validando o usuario");
        var token = request.getHeader(AUTHORIZATION);

        log.info("Verificando se o email que está no token é o mesmo que está no path variable");
        var ss = VaultSecretsManager.getSecret("auth");
        Assert.notNull(ss, "Não foi possivel recuperar o valor da secret");
        var user = JwtEntity.getUser(token, ss.get("API_SECRET").toString());

        @SuppressWarnings("unchecked")
        Map<String, String> pathVariables = (Map<String, String>) request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
        String email = pathVariables.get("email");

        if (email.equals(user.getEmail())) {
            return;
        } else if (!CollectionUtils.isEmpty(user.getPerfis()) &&
                new HashSet<>(user.getPerfis()).containsAll(Arrays.asList(PerfilEnum.ROLE_ADMIN, PerfilEnum.ROLE_APPLICATION))) {
            return;
        }

        log.error("Usuario não autorizado a acessar a informação");
        throw new AuthorizationException("Usuario não autorizado a acessar a informação.");
    }
}
