package com.alibaba.druid.filter.config;

import com.google.common.base.MoreObjects;

public class VaultConfig {
    private String gateway;
    private String authType;
    private String token;
    private String decryptKey;

    public String getGateway() {
        return gateway;
    }

    public void setGateway(String gateway) {
        this.gateway = gateway;
    }

    public String getAuthType() {
        return authType;
    }

    public void setAuthType(String authType) {
        this.authType = authType;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getDecryptKey() {
        return decryptKey;
    }

    public void setDecryptKey(String decryptKey) {
        this.decryptKey = decryptKey;
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("gateway", gateway)
                .add("authType", authType)
                .add("token", token)
                .add("decryptKey", decryptKey)
                .toString();
    }
}
