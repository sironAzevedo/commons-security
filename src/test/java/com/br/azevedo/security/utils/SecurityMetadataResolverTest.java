package com.br.azevedo.security.utils;

import com.br.azevedo.security.EnableSecurity;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.mockito.Mockito;
import org.springframework.context.ApplicationContext;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.method.HandlerMethod;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class SecurityMetadataResolverTest {

    private SecurityMetadataResolver resolver;

    @BeforeEach
    void setUp() {
        resolver = new SecurityMetadataResolver();
    }

    @Test
    @DisplayName("Cenário 15 - Deve reconhecer URLs públicas padrão do sistema via isPublicUrl()")
    void shouldRecognizeSystemPublicUrls() {
        assertTrue(resolver.isPublicUrl("/health", null));
        assertTrue(resolver.isPublicUrl("/health/live", null));
        assertTrue(resolver.isPublicUrl("/actuator/info", null));
        assertTrue(resolver.isPublicUrl("/swagger-ui/index.html", null));
        assertTrue(resolver.isPublicUrl("/swagger-ui.html", null));
        assertTrue(resolver.isPublicUrl("/v3/api-docs", null));
        assertTrue(resolver.isPublicUrl("/public/asset.css", null));
        assertTrue(resolver.isPublicUrl("/favicon.ico", null));

        assertFalse(resolver.isPublicUrl("/api/usuarios", null));
        assertFalse(resolver.isPublicUrl("/admin/settings", null));
    }

    @Test
    @DisplayName("Cenário 6 - Deve reconhecer publicPaths definidos na anotação global")
    void shouldRecognizeGlobalPublicPaths() {
        EnableSecurity globalSecurity = mock(EnableSecurity.class);
        when(globalSecurity.publicPaths()).thenReturn(new String[]{"/custom-public.*", "/auth/login"});

        assertTrue(resolver.isPublicUrl("/custom-public/test", globalSecurity));
        assertTrue(resolver.isPublicUrl("/auth/login", globalSecurity));
        assertFalse(resolver.isPublicUrl("/custom-private", globalSecurity));
    }

    @Test
    @DisplayName("Cenário 6 - Deve reconhecer publicMethods configurados na anotação local ou global")
    void shouldRecognizePublicMethods() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn("/api/produtos");
        when(request.getMethod()).thenReturn("GET");

        EnableSecurity localSecurity = mock(EnableSecurity.class);
        when(localSecurity.publicMethods()).thenReturn(new RequestMethod[]{RequestMethod.GET});
        when(localSecurity.publicPaths()).thenReturn(new String[0]);

        assertTrue(resolver.isPublicRequest(request, null, null, localSecurity));

        // Para POST no mesmo endpoint, deve retornar false se não configurado
        when(request.getMethod()).thenReturn("POST");
        assertFalse(resolver.isPublicRequest(request, null, null, localSecurity));
    }

    @Test
    @DisplayName("Cenário 6 - Deve reconhecer publicPaths configurados na anotação local do método")
    void shouldRecognizeLocalPublicPaths() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn("/api/produtos/livres/123");
        when(request.getMethod()).thenReturn("POST");

        EnableSecurity localSecurity = mock(EnableSecurity.class);
        when(localSecurity.publicMethods()).thenReturn(new RequestMethod[0]);
        when(localSecurity.publicPaths()).thenReturn(new String[]{"/api/produtos/livres/.*"});

        assertTrue(resolver.isPublicRequest(request, null, null, localSecurity));
    }

    @Test
    @DisplayName("Deve extrair anotação local a partir de HandlerMethod")
    void shouldExtractLocalAnnotationFromHandlerMethod() throws NoSuchMethodException {
        class DummyController {
            @EnableSecurity(publicPaths = {"/dummy"})
            public void dummyMethod() {}
        }

        DummyController dummy = new DummyController();
        HandlerMethod handlerMethod = new HandlerMethod(dummy, dummy.getClass().getMethod("dummyMethod"));

        EnableSecurity extracted = resolver.getLocalSecurityAnnotation(handlerMethod);
        assertNotNull(extracted);
        assertArrayEquals(new String[]{"/dummy"}, extracted.publicPaths());
    }

    @Test
    @DisplayName("Deve ignorar anotação @EnableSecurity em Controllers ao buscar global security")
    void shouldIgnoreControllersWhenResolvingGlobalSecurity() {
        ApplicationContext appCtx = mock(ApplicationContext.class);

        @org.springframework.web.bind.annotation.RestController
        @EnableSecurity
        class TestController {}

        when(appCtx.getBeansWithAnnotation(EnableSecurity.class))
                .thenReturn(Map.of("testController", new TestController()));

        EnableSecurity global = resolver.getGlobalSecurityAnnotation(appCtx);
        assertNull(global, "Controller anotado com @EnableSecurity não deve ser considerado global");
    }

    @Test
    @DisplayName("Deve resolver anotação global quando presente na classe principal/configuração")
    void shouldResolveGlobalSecurityFromAppConfigClass() {
        ApplicationContext appCtx = mock(ApplicationContext.class);

        @EnableSecurity(publicPaths = {"/app-public"})
        class MainApp {}

        when(appCtx.getBeansWithAnnotation(EnableSecurity.class))
                .thenReturn(Map.of("mainApp", new MainApp()));

        EnableSecurity global = resolver.getGlobalSecurityAnnotation(appCtx);
        assertNotNull(global);
        assertArrayEquals(new String[]{"/app-public"}, global.publicPaths());
    }
}
