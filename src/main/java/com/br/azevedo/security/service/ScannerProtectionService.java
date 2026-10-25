package com.br.azevedo.security.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Serviço responsável por identificar e mitigar requisições automatizadas de scanners
 * de vulnerabilidades (bots) e filtrar IPs bloqueados antes do pipeline de autorização.
 */
@Slf4j
@Service
public class ScannerProtectionService {

    private static final String UNKNOWN = "UNKNOWN";
    private static final String HEADER_X_FORWARDED_FOR = "X-Forwarded-For";
    private static final String HEADER_X_REAL_IP = "X-Real-IP";

    private final boolean scannerProtectionEnabled;
    private final Set<String> blockedIps;
    private final Set<String> blockedExtensions;
    private final Set<String> blockedPathPrefixes;

    private static final Set<String> DEFAULT_BLOCKED_EXTENSIONS = Set.of(
            ".php", ".asp", ".aspx", ".jsp", ".jspx", ".cgi", ".env", ".git",
            ".bak", ".sql", ".ini", ".conf", ".sh", ".pl"
    );

    private static final Set<String> DEFAULT_BLOCKED_PATH_PREFIXES = Set.of(
            "/wp-admin", "/wp-includes", "/wp-content", "/wp-login", "/wp-json",
            "/phpmyadmin", "/pma", "/cgi-bin", "/.env", "/.git"
    );

    @Autowired
    public ScannerProtectionService(Environment environment) {
        if (environment != null) {
            String enabledProp = environment.getProperty("security.scanner-protection.enabled");
            if (StringUtils.isBlank(enabledProp)) {
                enabledProp = environment.getProperty("security.scanner-protection.enabled", "true");
            }
            this.scannerProtectionEnabled = StringUtils.isBlank(enabledProp) || Boolean.parseBoolean(enabledProp);

            String blockedIpsProp = environment.getProperty("security.blocked-ips", "");
            if (StringUtils.isNotBlank(blockedIpsProp)) {
                this.blockedIps = Arrays.stream(blockedIpsProp.split(","))
                        .map(String::trim)
                        .filter(StringUtils::isNotBlank)
                        .collect(Collectors.toSet());
            } else {
                this.blockedIps = Collections.emptySet();
            }
        } else {
            this.scannerProtectionEnabled = true;
            this.blockedIps = Collections.emptySet();
        }

        this.blockedExtensions = DEFAULT_BLOCKED_EXTENSIONS;
        this.blockedPathPrefixes = DEFAULT_BLOCKED_PATH_PREFIXES;
    }

    public ScannerProtectionService() {
        this(null);
    }

    /**
     * Avalia se a requisição é permitida. Caso seja de um IP bloqueado ou de um scanner conhecido,
     * responde com status adequado (403 ou 404) e retorna false.
     *
     * @param request  a requisição HTTP
     * @param response a resposta HTTP
     * @return true se a requisição pode prosseguir no interceptor, false se foi bloqueada
     */
    public boolean isAllowed(HttpServletRequest request, HttpServletResponse response) {
        if (request == null) {
            return true;
        }

        String clientIp = extractClientIp(request);

        // 1. Verificação de IP bloqueado (Blacklist)
        if (isIpBlocked(clientIp)) {
            log.warn("Blocked request from blacklisted IP: ip={} method={} uri={}",
                    clientIp, request.getMethod(), request.getRequestURI());
            try {
                if (response != null) {
                    response.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden");
                }
            } catch (IOException e) {
                log.debug("Error writing 403 response for blocked IP: {}", e.getMessage());
            }
            return false;
        }

        // 2. Verificação de Scanner / Path Malicioso
        if (scannerProtectionEnabled && isMaliciousScannerPath(request.getRequestURI())) {
            log.debug("Scanner probe blocked: method={} uri={} ip={}",
                    request.getMethod(), request.getRequestURI(), clientIp);
            try {
                if (response != null) {
                    response.sendError(HttpServletResponse.SC_NOT_FOUND, "Not Found");
                }
            } catch (IOException e) {
                log.debug("Error writing 404 response for scanner probe: {}", e.getMessage());
            }
            return false;
        }

        return true;
    }

    /**
     * Verifica se o IP está na lista de bloqueados.
     */
    public boolean isIpBlocked(String ip) {
        if (StringUtils.isBlank(ip) || blockedIps.isEmpty()) {
            return false;
        }
        return blockedIps.contains(ip.trim());
    }

    /**
     * Detecta se a URI corresponde a um padrão comum de scanner de vulnerabilidade.
     */
    public boolean isMaliciousScannerPath(String uri) {
        if (StringUtils.isBlank(uri)) {
            return false;
        }

        String normalizedUri = uri.toLowerCase(Locale.ROOT).replaceAll("/+", "/");

        // Checar extensões bloqueadas
        for (String ext : blockedExtensions) {
            if (normalizedUri.endsWith(ext) || normalizedUri.contains(ext + "/") || normalizedUri.contains(ext + "?")) {
                return true;
            }
        }

        // Checar prefixos ou caminhos conhecidos de exploits/scanners
        for (String prefix : blockedPathPrefixes) {
            if (normalizedUri.startsWith(prefix) || normalizedUri.contains(prefix + "/")) {
                return true;
            }
        }

        return false;
    }

    /**
     * Extrai o IP real do cliente considerando proxies e balanceadores de carga.
     */
    public String extractClientIp(HttpServletRequest request) {
        if (request == null) {
            return UNKNOWN;
        }
        String xForwardedFor = request.getHeader(HEADER_X_FORWARDED_FOR);
        if (StringUtils.isNotBlank(xForwardedFor) && !UNKNOWN.equalsIgnoreCase(xForwardedFor)) {
            return xForwardedFor.split(",")[0].trim();
        }
        String xRealIp = request.getHeader(HEADER_X_REAL_IP);
        if (StringUtils.isNotBlank(xRealIp) && !UNKNOWN.equalsIgnoreCase(xRealIp)) {
            return xRealIp.trim();
        }
        return StringUtils.defaultIfBlank(request.getRemoteAddr(), UNKNOWN);
    }
}
