package com.br.azevedo.security;

import com.br.azevedo.security.secretMnager.VaultSecretsManagerTest;

public class Main {

    public static void main(String[] args) {
        var secret = VaultSecretsManagerTest.getSecret("auth");
        System.out.println(secret.get("API_SECRET").toString());
    }
}
