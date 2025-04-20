package com.br.azevedo.security.models.jwt;

import com.br.azevedo.exception.AuthenticationException;
import com.br.azevedo.model.dto.UserDTO;
import com.br.azevedo.utils.JsonUtils;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.apache.commons.lang3.ObjectUtils;

import static com.br.azevedo.security.utils.Constantes.APPLICATION;
import static org.apache.commons.lang3.ObjectUtils.isEmpty;

public class TokenMapper {
    private static final String EMPTY_SPACE = " ";
    private static final Integer TOKEN_INDEX = 1;

    public static Object get(String token, String apiSecret) {
        var accessToken = extractToken(token);
        var claims = Jwts
                .parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(apiSecret.getBytes()))
                .build()
                .parseClaimsJws(accessToken)
                .getBody();


        var type = claims.get("type");
        if (ObjectUtils.isEmpty(type)) {
            throw new AuthenticationException("Token is not valid.");
        }

        if (APPLICATION.equals(type)) {
            var user = JsonUtils.objetcToJson(claims.get("authApp"));
            return JsonUtils.jsonToObject(user, AppEntity.class);
        }

        var app = JsonUtils.objetcToJson(claims.get("authUser"));
        return JsonUtils.jsonToObject(app, UserDTO.class);
    }

    private static String extractToken(String token) {
        if (isEmpty(token)) {
            throw new AuthenticationException("The access token was not informed.");
        }
        if (token.contains(EMPTY_SPACE)) {
            return token.split(EMPTY_SPACE)[TOKEN_INDEX];
        }
        return token;
    }
}
