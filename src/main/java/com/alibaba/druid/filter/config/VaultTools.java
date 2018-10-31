package com.alibaba.druid.filter.config;

import org.springframework.core.io.FileSystemResource;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.util.Base64Utils;
import org.springframework.vault.authentication.ClientAuthentication;
import org.springframework.vault.authentication.ClientCertificateAuthentication;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultClients;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.config.ClientHttpRequestFactoryFactory;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.ClientOptions;
import org.springframework.vault.support.SslConfiguration;
import org.springframework.vault.support.VaultResponse;
import org.springframework.web.client.RestTemplate;

import java.io.File;
import java.net.URI;

import static com.google.common.base.Preconditions.checkNotNull;


public class VaultTools {

    /*客户端认证方式-tls证书认证*/
    public static final String VAULT_AUTH_TYPE_CERT = "cert";
    /*客户端tls证书认证参数名*/
    public static final String VAULT_CLIENT_SSL_KEY_STORE = "vault.client.ssl.keyStore";
    public static final String VAULT_CLIENT_SSL_KEY_STORE_PWD = "vault.client.ssl.keyStorePwd";

    private String decryptKey;
    private String keyStore;
    private String keyStorePassword;
    private VaultOperations operations;

    public VaultTools() {
    }

    public VaultTools(String gateway, String authType, String decryptKey, String token) throws Exception {
        VaultConfig vaultConfig = new VaultConfig();
        vaultConfig.setGateway(gateway);
        vaultConfig.setAuthType(authType);
        vaultConfig.setDecryptKey(decryptKey);
        vaultConfig.setToken(token);
        init(vaultConfig);
    }

    public VaultTools(VaultConfig vaultConfig) throws Exception {
        init(vaultConfig);
    }

    public void setDecryptKey(String decryptKey) {
        this.decryptKey = decryptKey;
    }

    public void setKeyStore(String keyStore) {
        this.keyStore = keyStore;
    }

    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }

    private void init(VaultConfig vaultProp) throws Exception {
        checkNotNull(vaultProp.getGateway(), "vault网关不能为空");
        String gateway = vaultProp.getGateway();
        String authType = vaultProp.getAuthType();
        setDecryptKey(vaultProp.getDecryptKey());
        setKeyStore(System.getProperty(VAULT_CLIENT_SSL_KEY_STORE));
        setKeyStorePassword(System.getProperty(VAULT_CLIENT_SSL_KEY_STORE_PWD));
        VaultEndpoint vaultEndpoint = VaultEndpoint.from(new URI(gateway));
        ClientAuthentication authentication;

        if (VAULT_AUTH_TYPE_CERT.equals(authType)) {
            ClientHttpRequestFactory clientHttpRequestFactory = ClientHttpRequestFactoryFactory.create(new ClientOptions(), prepareCertAuthenticationMethod());
            RestTemplate restTemplate = VaultClients.createRestTemplate(vaultEndpoint, clientHttpRequestFactory);
            authentication = new ClientCertificateAuthentication(restTemplate);
        } else {
            checkNotNull(vaultProp.getToken(), "token不能为空");
            authentication = new TokenAuthentication(vaultProp.getToken());
        }
        this.operations = new VaultTemplate(vaultEndpoint, authentication);
    }

    private SslConfiguration prepareCertAuthenticationMethod() {
        return SslConfiguration.forKeyStore(new FileSystemResource(new File(keyStore)), keyStorePassword.toCharArray());
    }

    public String decrypt(String cipherText) {
        VaultResponse vaultResponse = operations.write(decryptKey, "{\"ciphertext\": \"" + cipherText + "\"}");
        String plaintext = (String) vaultResponse.getData().get("plaintext");
        String result = new String(Base64Utils.decodeFromString(plaintext));
        return result;
    }
}
