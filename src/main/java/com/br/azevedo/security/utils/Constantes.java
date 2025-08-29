package com.br.azevedo.security.utils;

import org.springframework.http.HttpHeaders;

import java.util.Set;
import java.util.regex.Pattern;

public final class Constantes {

    private Constantes() {}
    public static final String AUTHORIZATION = HttpHeaders.AUTHORIZATION;
    public static final String TRANSACTION_ID = "transactionid";
    public final static Pattern UUID_REGEX_PATTERN =
            Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

    public static final String APPLICATION = "application";

    public static final Set<Pattern> PUBLIC_URLS = Set.of(
            Pattern.compile("/public.*"),        // Libera /public, /public/css, etc.
            Pattern.compile("/favicon.*"),        // Libera /public, /public/css, etc.
            Pattern.compile("/health.*"),        // Libera /health e /health/live
            Pattern.compile("/actuator.*"),      // Libera tudo sob /actuator
            Pattern.compile("/error"),
            Pattern.compile("/v3/api-docs.*"),   // Libera /v3/api-docs e /v3/api-docs/swagger-config
            Pattern.compile("/swagger-ui.*"),    // Libera /swagger-ui e /swagger-ui/index.html
            Pattern.compile("/swagger-ui.html")  // Corrigido: com a barra no início
    );
}
