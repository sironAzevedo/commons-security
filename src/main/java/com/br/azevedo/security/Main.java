package com.br.azevedo.security;

import com.br.azevedo.security.secretMnager.VaultSecretsManager;
import org.springframework.util.Assert;

public class Main {

    public static void main(String[] args) {
        var secret = VaultSecretsManager.getSecret("auth");
        System.out.println(secret.get("API_SECRET").toString());
    }
}
