package com.br.azevedo.security.models.Deserializer;

import com.br.azevedo.model.enums.PerfilEnum;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class SafePerfilEnumListDeserializer extends JsonDeserializer<List<PerfilEnum>> {

    @Override
    public List<PerfilEnum> deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        List<PerfilEnum> result = new ArrayList<>();
        JsonNode node = p.getCodec().readTree(p);

        if (node.isArray()) {
            for (JsonNode child : node) {
                try {
                    result.add(PerfilEnum.valueOf(child.asText()));
                } catch (IllegalArgumentException e) {
                    // Ignora valores inválidos
                }
            }
        }
        return result;
    }
}