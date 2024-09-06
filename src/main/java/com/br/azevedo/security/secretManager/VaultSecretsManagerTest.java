package com.br.azevedo.security.secretManager;

//@Slf4j
public class VaultSecretsManagerTest {

//    private static final String VAULT_TOKEN = "s.AfKqVJZjngy3dMHqa53Mkrj5";
//    private static VaultTemplate vaultTemplate;
//
//    static {
//        try {
//            vaultTemplate = new VaultTemplate(
//                    VaultEndpoint.from(new URI("http://127.0.0.1:8200")),
//                    new TokenAuthentication(VAULT_TOKEN)
//            );
//        } catch (VaultException e) {
//            e.printStackTrace();
//        } catch (URISyntaxException e) {
//            throw new RuntimeException(e);
//        }
//    }
//
//    public static void createOrUpdateSecret(String path, Map<String, Object> data) {
//        try {
//            Versioned.Metadata createResponse = vaultTemplate
//                    .opsForVersionedKeyValue("secret")
//                    .put(path, data);
//
//            log.info("Secret written successfully. {}", createResponse.getVersion());
//        } catch (VaultException e) {
//            e.printStackTrace();
//        }
//    }
//
//
//    @SuppressWarnings("unchecked")
//    public static Map<String, Object> getSecret(String path) {
//        return (Map<String, Object>) Objects.requireNonNull(
//                Objects.requireNonNull(vaultTemplate.read("secret/data/".concat(path)))
//                        .getData()).get("data");
//    }
//
//    public static void deleteSecret(String path) {
//        try {
//
//            vaultTemplate.delete(path);
//            log.info("Secret deleted: {}", path);
//        } catch (VaultException e) {
//            e.printStackTrace();
//        }
//    }
}
