/*
 * Copyright 1999-2018 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.alibaba.druid.filter.config;

import com.alibaba.druid.filter.FilterAdapter;
import com.alibaba.druid.pool.DruidDataSource;
import com.alibaba.druid.pool.DruidDataSourceFactory;
import com.alibaba.druid.proxy.jdbc.DataSourceProxy;
import com.alibaba.druid.support.logging.Log;
import com.alibaba.druid.support.logging.LogFactory;
import com.alibaba.druid.util.JdbcUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.Properties;

public class VaultFilter extends FilterAdapter {
    private static Log LOG = LogFactory.getLog(VaultFilter.class);

    public static final String VAULT_GATEWAY = "vault.gateway";
    public static final String VAULT_AUTHTYPE = "vault.authType";
    public static final String VAULT_TOKEN = "vault.token";
    public static final String VAULT_DECRYPTPATH = "vault.decryptPath";

    public VaultFilter() {
    }

    public void init(DataSourceProxy dataSourceProxy) {
        if (!(dataSourceProxy instanceof DruidDataSource)) {
            LOG.error("ConfigLoader only support DruidDataSource");
        }
        DruidDataSource dataSource = (DruidDataSource) dataSourceProxy;
        Properties connectionProperties = dataSource.getConnectProperties();

        Properties configFileProperties = loadPropertyFromConfigFile(connectionProperties);

        decrypt(dataSource, configFileProperties);
    }

    public void decrypt(DruidDataSource dataSource, Properties info) {

        try {
            String encryptedPassword = dataSource.getPassword();
            String gateway = info.getProperty(VAULT_GATEWAY);
            String authType = info.getProperty(VAULT_AUTHTYPE);
            String token = info.getProperty(VAULT_TOKEN);
            String decryptPath = info.getProperty(VAULT_DECRYPTPATH);

            String passwordPlainText = new VaultTools(gateway, authType, decryptPath, token).decrypt(encryptedPassword);

            if (info != null) {
                info.setProperty(DruidDataSourceFactory.PROP_PASSWORD, passwordPlainText);
            } else {
                dataSource.setPassword(passwordPlainText);
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to decrypt.", e);
        }
    }

    Properties loadPropertyFromConfigFile(Properties connectionProperties) {
        String configFile = "classpath:vault.properties";
        Properties info = loadConfig(configFile);

        if (info == null) {
            throw new IllegalArgumentException("Cannot load remote config file from the [config.file=" + configFile
                    + "].");
        }
        return info;
    }

    public Properties loadConfig(String filePath) {
        Properties properties = new Properties();

        InputStream inStream = null;
        try {
            if (filePath.startsWith("file://")) {
                filePath = filePath.substring("file://".length());
                inStream = getFileAsStream(filePath);
            } else if (filePath.startsWith("classpath:")) {
                String resourcePath = filePath.substring("classpath:".length());
                inStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(resourcePath);
            } else {
                inStream = getFileAsStream(filePath);
            }
            if (inStream == null) {
                LOG.error("load vault config file error, file : " + filePath);
                return null;
            }
            properties.load(inStream);
            return properties;
        } catch (Exception ex) {
            LOG.error("load config file error, file : " + filePath, ex);
            return null;
        } finally {
            JdbcUtils.close(inStream);
        }
    }

    private InputStream getFileAsStream(String filePath) throws FileNotFoundException {
        InputStream inStream = null;
        File file = new File(filePath);
        if (file.exists()) {
            inStream = new FileInputStream(file);
        } else {
            inStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(filePath);
        }
        return inStream;
    }
}
