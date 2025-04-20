package com.br.azevedo.security.models.jwt;

import com.br.azevedo.model.enums.PerfilEnum;
import com.br.azevedo.security.models.Deserializer.SafePerfilEnumListDeserializer;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;

import java.util.List;

@Getter
public class AppEntity {

    @NotEmpty
    private String clientId;

    @NotEmpty
    @JsonDeserialize(using = SafePerfilEnumListDeserializer.class)
    private List<PerfilEnum> perfis;

    @NotEmpty
    private String scopes;

    @NotEmpty
    private String origen;


}
