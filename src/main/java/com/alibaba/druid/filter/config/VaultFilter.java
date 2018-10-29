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

import java.util.Properties;

public class VaultFilter extends FilterAdapter {

    private static Log         LOG                     = LogFactory.getLog(VaultFilter.class);

    public static final String CONFIG_FILE             = "config.file";
    public static final String CONFIG_DECRYPT          = "config.decrypt";
    public static final String CONFIG_KEY              = "config.decrypt.key";

    public static final String SYS_PROP_CONFIG_FILE    = "druid.config.file";
    public static final String SYS_PROP_CONFIG_DECRYPT = "druid.config.decrypt";
    public static final String SYS_PROP_CONFIG_KEY     = "druid.config.decrypt.key";

    public VaultFilter(){
    }

    public void init(DataSourceProxy dataSourceProxy) {
        if (!(dataSourceProxy instanceof DruidDataSource)) {
            LOG.error("ConfigLoader only support DruidDataSource");
        }
        DruidDataSource dataSource = (DruidDataSource) dataSourceProxy;

        decrypt(dataSource, null);
    }

    public void decrypt(DruidDataSource dataSource, Properties info) {

        try {
            String encryptedPassword = null;
            if (info != null) {
                encryptedPassword = info.getProperty(DruidDataSourceFactory.PROP_PASSWORD);
            }

            if (encryptedPassword == null || encryptedPassword.length() == 0) {
                encryptedPassword = dataSource.getConnectProperties().getProperty(DruidDataSourceFactory.PROP_PASSWORD);
            }

            if (encryptedPassword == null || encryptedPassword.length() == 0) {
                encryptedPassword = dataSource.getPassword();
            }


            String passwordPlainText = new VaultTools().decrypt(encryptedPassword);

            if (info != null) {
                info.setProperty(DruidDataSourceFactory.PROP_PASSWORD, passwordPlainText);
            } else {
                dataSource.setPassword(passwordPlainText);
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to decrypt.", e);
        }
    }
}
