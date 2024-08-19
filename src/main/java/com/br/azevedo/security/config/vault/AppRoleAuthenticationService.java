package com.br.azevedo.security.config.vault;

import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.socket.PlainConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.URIScheme;
import org.apache.hc.core5.http.config.Registry;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.springframework.context.ApplicationContext;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.vault.authentication.AppRoleAuthentication;
import org.springframework.vault.authentication.AppRoleAuthenticationOptions;
import org.springframework.vault.authentication.ClientAuthentication;
import org.springframework.vault.client.VaultClients;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.config.AbstractVaultConfiguration;
import org.springframework.web.client.RestOperations;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

public class AppRoleAuthenticationService extends AbstractVaultConfiguration {

    private String roleId;
    private String secretId;
    private String host;

    public AppRoleAuthenticationService(String roleId,
                                        String secretId,
                                        String host,
                                        ApplicationContext applicationContext) {
        this.roleId = roleId;
        this.secretId = secretId;
        this.host = host;
        this.setApplicationContext(applicationContext);
    }

    @Override
    public VaultEndpoint vaultEndpoint() {
        return VaultEndpoint.from(URI.create(this.host));
    }

    @Override
    public ClientAuthentication clientAuthentication() {
        try {
            RestOperations restOperations = VaultClients.createRestTemplate(VaultEndpoint.from(URI.create(this.host)), disableSSlHttpClient5());
            AppRoleAuthenticationOptions options = AppRoleAuthenticationOptions.builder()
                    .roleId(AppRoleAuthenticationOptions.RoleId.provided(roleId))
                    .secretId(AppRoleAuthenticationOptions.SecretId.provided(secretId)).build();
            return new AppRoleAuthentication(options, restOperations);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private HttpComponentsClientHttpRequestFactory disableSSlHttpClient5()
            throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException {

        SSLContext sslContext = SSLContextBuilder.create()
                .loadTrustMaterial((X509Certificate[] certificateChain, String authType) -> true)  // <--- accepts each certificate
                .build();

        Registry<ConnectionSocketFactory> socketRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register(URIScheme.HTTPS.getId(), new SSLConnectionSocketFactory(sslContext))
                .register(URIScheme.HTTP.getId(), new PlainConnectionSocketFactory())
                .build();

        CloseableHttpClient httpClient = HttpClientBuilder.create()
                .setConnectionManager(new PoolingHttpClientConnectionManager(socketRegistry))
                .setConnectionManagerShared(true)
                .build();


        return new HttpComponentsClientHttpRequestFactory(httpClient);
    }
}
