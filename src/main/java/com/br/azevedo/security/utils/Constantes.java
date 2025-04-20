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
            Pattern.compile("/health/.*"),
            Pattern.compile(".*/public/.*"),
            Pattern.compile(".*/actuator/.*"),
            Pattern.compile(".*/error/.*"),
            Pattern.compile("/v3/api-docs/.*"),
            Pattern.compile("/swagger-ui/.*"),
            Pattern.compile("swagger-ui.html")
    );
}
