/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.recovery.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementClientException;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.recovery.IdentityRecoveryConstants;
import org.wso2.carbon.identity.recovery.IdentityRecoveryServerException;
import org.wso2.carbon.identity.recovery.handler.function.ResourceToProperties;
import org.wso2.carbon.identity.recovery.internal.IdentityRecoveryServiceDataHolder;
import org.wso2.carbon.identity.recovery.util.Utils;

import java.util.Map;

/**
 * Config store based property handler.
 */
public class ConfigStoreFeatureLockPropertyHandler {

    private static final Log log = LogFactory.getLog(ConfigStoreFeatureLockPropertyHandler.class);

    private static ConfigStoreFeatureLockPropertyHandler instance = new ConfigStoreFeatureLockPropertyHandler();

    public static ConfigStoreFeatureLockPropertyHandler getInstance() {

        return instance;
    }

    private ConfigStoreFeatureLockPropertyHandler() {

    }

    public Map<String, String> getConfigStoreProperties(String tenantDomain, String featureId)
            throws IdentityRecoveryServerException {

        Map<String, String> properties;
        try {
            FrameworkUtils.startTenantFlow(tenantDomain);
            try {
                if (!isFeatureLockResourceTypeNotExists()) {
                    Resource resource =
                            IdentityRecoveryServiceDataHolder.getInstance().getConfigurationManager()
                                    .getResource(IdentityRecoveryConstants.FEATURE_LOCK_RESOURCE_TYPE, featureId);
                    properties = new ResourceToProperties().apply(resource);
                } else {
                    throw new UnsupportedOperationException("User Feature properties are not configured.");
                }

            } catch (ConfigurationManagementException e) {
                throw Utils.handleServerException(
                        IdentityRecoveryConstants.ErrorMessages.ERROR_CODE_FAILED_TO_FETCH_RESOURCE_FROM_CONFIG_STORE,
                        null);
            }
        } finally {
            FrameworkUtils.endTenantFlow();
        }
        return properties;
    }

    /**
     * Returns true if the Feature Lock type is already in the ConfigurationManager.
     *
     * @return {@code true} if the Feature Lock resource type is already in the ConfigurationManager,
     * {@code false} otherwise.
     * @throws ConfigurationManagementException
     */
    private boolean isFeatureLockResourceTypeNotExists() throws ConfigurationManagementException {

        try {
            IdentityRecoveryServiceDataHolder.getInstance().getConfigurationManager()
                    .getResourceType(IdentityRecoveryConstants.FEATURE_LOCK_RESOURCE_TYPE);
        } catch (ConfigurationManagementClientException e) {
            if (ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_TYPE_DOES_NOT_EXISTS.getCode()
                    .equals(e.getErrorCode())) {
                return true;
            }
            throw e;
        }
        return false;
    }
}
