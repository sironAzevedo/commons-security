package com.br.azevedo.security.utils;

import com.br.azevedo.security.EnableSecurity;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.method.HandlerMethod;

import java.net.URI;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

import static com.br.azevedo.security.utils.Constantes.PUBLIC_URLS;

/**
 * Utilitário e resolvedor de metadados de segurança para a anotação {@link EnableSecurity}.
 *
 * <p>Responsável por determinar:</p>
 * <ul>
 *   <li>Se a segurança está ativada no escopo global (classe principal da aplicação).</li>
 *   <li>Se um método handler/controller possui a anotação {@link EnableSecurity}.</li>
 *   <li>Se uma determinada requisição é considerada pública (seja por {@code isPublicUrl()},
 *       por {@code publicPaths} ou por {@code publicMethods}).</li>
 * </ul>
 */
@Component
public class SecurityMetadataResolver {

    private final PathMatcher pathMatcher = new AntPathMatcher();

    /**
     * Localiza a anotação {@link EnableSecurity} configurada no escopo global (na classe principal da aplicação ou configuração).
     *
     * @param applicationContext o contexto do Spring.
     * @return a anotação {@link EnableSecurity} global ou null se não encontrada.
     */
    public EnableSecurity getGlobalSecurityAnnotation(ApplicationContext applicationContext) {
        if (applicationContext == null) {
            return null;
        }

        return applicationContext.getBeansWithAnnotation(EnableSecurity.class)
                .values()
                .stream()
                .filter(bean -> {
                    Class<?> targetClass = bean.getClass();
                    boolean isController = AnnotationUtils.findAnnotation(targetClass, Controller.class) != null
                            || AnnotationUtils.findAnnotation(targetClass, RestController.class) != null;
                    return !isController;
                })
                .map(bean -> AnnotationUtils.findAnnotation(bean.getClass(), EnableSecurity.class))
                .filter(ObjectUtils::isNotEmpty)
                .findFirst()
                .orElse(null);
    }

    /**
     * Localiza a anotação {@link EnableSecurity} no método específico ou na classe do Controller.
     *
     * @param handler o handler da requisição interceptada.
     * @return a anotação {@link EnableSecurity} do método/controller ou null.
     */
    public EnableSecurity getLocalSecurityAnnotation(Object handler) {
        if (handler instanceof HandlerMethod handlerMethod) {
            EnableSecurity methodAnnotation = AnnotationUtils.findAnnotation(handlerMethod.getMethod(), EnableSecurity.class);
            if (methodAnnotation != null) {
                return methodAnnotation;
            }
            return AnnotationUtils.findAnnotation(handlerMethod.getBeanType(), EnableSecurity.class);
        }
        return null;
    }

    /**
     * Determina se a URL recebida é pública com base na regra existente em {@code PUBLIC_URLS}
     * e nas configurações de {@code publicPaths} da anotação global fornecida.
     *
     * @param url a URI da requisição.
     * @param globalSecurity a anotação global, se houver.
     * @return true se for uma URL pública.
     */
    public boolean isPublicUrl(String url, EnableSecurity globalSecurity) {
        if (url == null) {
            return false;
        }

        String path = URI.create(url).getPath();
        Set<Pattern> publicPatterns = new HashSet<>(PUBLIC_URLS);

        if (globalSecurity != null && ArrayUtils.isNotEmpty(globalSecurity.publicPaths())) {
            Arrays.stream(globalSecurity.publicPaths())
                    .map(Pattern::compile)
                    .forEach(publicPatterns::add);
        }

        return publicPatterns.stream().anyMatch(pattern -> pattern.matcher(path).find());
    }

    /**
     * Avalia se uma requisição HTTP específica é pública com base em:
     * <ol>
     *   <li>Regra existente {@link #isPublicUrl(String, EnableSecurity)}.</li>
     *   <li>Configuração de {@code publicPaths} ou {@code publicMethods} na anotação do método/controller.</li>
     *   <li>Configuração de {@code publicMethods} na anotação global.</li>
     * </ol>
     *
     * @param request a requisição HTTP.
     * @param handler o handler interceptado.
     * @param globalAnnotation a anotação global se presente.
     * @param localAnnotation a anotação local se presente.
     * @return true se o endpoint puder ser acessado publicamente.
     */
    public boolean isPublicRequest(HttpServletRequest request, Object handler, EnableSecurity globalAnnotation, EnableSecurity localAnnotation) {
        String requestUri = request.getRequestURI();
        String httpMethodName = request.getMethod();

        // 1. Regra existente isPublicUrl
        if (isPublicUrl(requestUri, globalAnnotation)) {
            return true;
        }

        // 2. Verificar publicMethods da anotação global
        if (globalAnnotation != null && isMethodConfiguredAsPublic(httpMethodName, globalAnnotation.publicMethods())) {
            return true;
        }

        // 3. Verificar publicPaths e publicMethods da anotação local
        if (localAnnotation != null) {
            if (isMethodConfiguredAsPublic(httpMethodName, localAnnotation.publicMethods())) {
                return true;
            }
            if (isPathConfiguredAsPublic(requestUri, localAnnotation.publicPaths())) {
                return true;
            }
        }

        return false;
    }

    private boolean isMethodConfiguredAsPublic(String httpMethodName, RequestMethod[] publicMethods) {
        if (ArrayUtils.isEmpty(publicMethods)) {
            return false;
        }
        return Arrays.stream(publicMethods)
                .anyMatch(reqMethod -> reqMethod.name().equalsIgnoreCase(httpMethodName));
    }

    private boolean isPathConfiguredAsPublic(String uri, String[] publicPaths) {
        if (ArrayUtils.isEmpty(publicPaths)) {
            return false;
        }
        String path = URI.create(uri).getPath();
        for (String patternStr : publicPaths) {
            if (pathMatcher.match(patternStr, path)) {
                return true;
            }
            try {
                if (Pattern.compile(patternStr).matcher(path).find()) {
                    return true;
                }
            } catch (Exception ignored) {
                // Se não for um regex válido, ignora e confia no pathMatcher
            }
        }
        return false;
    }
}
