package com.br.azevedo.security.models.jwt;

import com.br.azevedo.exception.AuthenticationException;
import com.br.azevedo.model.dto.UserDTO;
import com.br.azevedo.utils.JsonUtils;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import static org.apache.commons.lang3.ObjectUtils.isEmpty;

public class JwtEntity extends UserDTO {
    private static final String EMPTY_SPACE = " ";
    private static final Integer TOKEN_INDEX = 1;

    public static JwtEntity getUser(String token, String apiSecret) {
        var accessToken = extractToken(token);
        var claims = Jwts
                .parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(apiSecret.getBytes()))
                .build()
                .parseClaimsJws(accessToken)
                .getBody();

        var authUser = JsonUtils.objetcToJson(claims.get("authUser"));
        return JsonUtils.jsonToObject(authUser, JwtEntity.class);
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
