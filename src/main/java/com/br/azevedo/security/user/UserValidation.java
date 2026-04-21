package com.br.azevedo.security.user;

import com.br.azevedo.security.service.TokenValidationStrategy;
import com.br.azevedo.security.strategy.TokenValidatorFactory;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

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
    private final TokenValidatorFactory tokenValidatorFactory;

    @Pointcut("@annotation(validationUser)")
    public void callAt(ValidationUser validationUser) {}

    @Before("callAt(validationUser)")
    public void checkAccess(ValidationUser validationUser) {
        var token = request.getHeader(AUTHORIZATION);
        TokenValidationStrategy strategy = tokenValidatorFactory.getStrategy(token);
        strategy.validate(request);
    }
}
