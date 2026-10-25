package com.br.azevedo.security.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.env.MockEnvironment;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ScannerProtectionServiceTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private MockEnvironment environment;
    private ScannerProtectionService service;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        environment = new MockEnvironment();
        service = new ScannerProtectionService(environment);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/wp-includes/Text/Diff/Engine/about.php",
            "/wp-admin/network/plugins.php",
            "/wp-admin/maint/index.php",
            "//wp-content/plugins/erinyani/",
            "/wp-content/uploads/",
            "/opsh.php",
            "/wp-filemannger4h.php",
            "/coffexiumimage.php",
            "/img.php",
            "/lowfile.php",
            "/class-walker-footer-dev.php",
            "/cheng.php",
            "/nex.php",
            "/lanbai.php",
            "/zv.php",
            "/cache.php",
            "/kgblegacy.php",
            "/Component.php",
            "/wsoby.php",
            "/zhidagen.php",
            "/fferr.php",
            "/wpconf.php",
            "/aoao.php",
            "/opomo.php",
            "/122.php",
            "/echkmss.php",
            "/lan.php",
            "/files/icon.php",
            "/pag.php",
            "/wp-content/uploads/dsa.php",
            "/trackback.php",
            "/wp_blog_foo.php",
            "/wp-json.php",
            "/file-B-G.php",
            "/wmc.php",
            "/3.php",
            "/waa.php",
            "/.env",
            "/.git/config",
            "/phpmyadmin/index.php"
    })
    @DisplayName("Deve identificar como maliciosas as URLs de bot/scanner conhecidas")
    void shouldIdentifyScannerPaths(String maliciousUri) throws IOException {
        when(request.getRequestURI()).thenReturn(maliciousUri);
        when(request.getRemoteAddr()).thenReturn("20.194.17.163");

        boolean allowed = service.isAllowed(request, response);

        assertFalse(allowed);
        verify(response).sendError(HttpServletResponse.SC_NOT_FOUND, "Not Found");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/api/v1/usuarios",
            "/api/v1/faturas",
            "/health",
            "/actuator/health",
            "/swagger-ui/index.html",
            "/public/css/style.css"
    })
    @DisplayName("Deve permitir requisições legítimas da aplicação")
    void shouldAllowLegitimatePaths(String legitimateUri) {
        when(request.getRequestURI()).thenReturn(legitimateUri);
        when(request.getRemoteAddr()).thenReturn("192.168.1.1");

        boolean allowed = service.isAllowed(request, response);

        assertTrue(allowed);
        verifyNoInteractions(response);
    }

    @Test
    @DisplayName("Deve bloquear IP presente na blacklist com 403 Forbidden")
    void shouldBlockBlacklistedIp() throws IOException {
        environment.setProperty("security.blocked-ips", "20.194.17.163, 198.51.100.5");
        service = new ScannerProtectionService(environment);

        when(request.getRequestURI()).thenReturn("/api/v1/usuarios");
        when(request.getRemoteAddr()).thenReturn("20.194.17.163");

        boolean allowed = service.isAllowed(request, response);

        assertFalse(allowed);
        verify(response).sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden");
    }

    @Test
    @DisplayName("Deve permitir requisições quando a proteção de scanner estiver desativada")
    void shouldAllowWhenScannerProtectionIsDisabled() {
        environment.setProperty("security.scanner-protection.enabled", "false");
        service = new ScannerProtectionService(environment);

        when(request.getRequestURI()).thenReturn("/wp-admin/index.php");
        when(request.getRemoteAddr()).thenReturn("10.0.0.1");

        boolean allowed = service.isAllowed(request, response);

        assertTrue(allowed);
        verifyNoInteractions(response);
    }

    @Test
    @DisplayName("Deve extrair o IP considerando o cabeçalho X-Forwarded-For")
    void shouldExtractClientIpFromXForwardedFor() throws IOException {
        environment.setProperty("security.blocked-ips", "20.194.17.163");
        service = new ScannerProtectionService(environment);

        when(request.getHeader("X-Forwarded-For")).thenReturn("20.194.17.163, 10.0.0.1");
        when(request.getRequestURI()).thenReturn("/api/v1/usuarios");

        boolean allowed = service.isAllowed(request, response);

        assertFalse(allowed);
        verify(response).sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden");
    }

    @Test
    @DisplayName("Deve extrair o IP considerando o cabeçalho X-Real-IP")
    void shouldExtractClientIpFromXRealIp() throws IOException {
        environment.setProperty("security.blocked-ips", "20.194.17.163");
        service = new ScannerProtectionService(environment);

        when(request.getHeader("X-Real-IP")).thenReturn("20.194.17.163");
        when(request.getRequestURI()).thenReturn("/api/v1/usuarios");

        boolean allowed = service.isAllowed(request, response);

        assertFalse(allowed);
        verify(response).sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden");
    }
}
