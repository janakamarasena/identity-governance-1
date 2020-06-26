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
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.mgt.constants.IdentityMgtConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;

import java.util.HashMap;
import java.util.Map;

/**
 * This event handler is used to handle events related to user meta data updates.
 */
public class IdentityUserMetadataMgtHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(IdentityUserMetadataMgtHandler.class);

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        Map<String, Object> eventProperties = event.getEventProperties();
        UserStoreManager userStoreManager = (UserStoreManager)
                eventProperties.get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER);

        if (IdentityEventConstants.Event.POST_AUTHENTICATION.equals(event.getEventName())) {
            handlePostAuthenticate(eventProperties, userStoreManager);
        } else if (IdentityEventConstants.Event.POST_UPDATE_CREDENTIAL.equals(event.getEventName()) ||
                IdentityEventConstants.Event.POST_UPDATE_CREDENTIAL_BY_ADMIN.equals(event.getEventName())) {

            handleCredentialUpdate(eventProperties, userStoreManager);
        }
    }

    private void handlePostAuthenticate(Map<String, Object> eventProperties, UserStoreManager userStoreManager)
            throws IdentityEventException {

        if (log.isDebugEnabled()) {
            log.debug("Start handling post authentication event.");
        }
        if (Boolean.parseBoolean((String) eventProperties.get(IdentityEventConstants.EventProperty.AUTHENTICATION_STATUS))) {
            String userName = (String) eventProperties.get(IdentityEventConstants.EventProperty.USER_NAME);
            String lastLoginTime = Long.toString(System.currentTimeMillis());
            Map<String, String> userClaims = new HashMap<>();
            userClaims.put(IdentityMgtConstants.LAST_LOGIN_TIME, lastLoginTime);
            try {
                userStoreManager.setUserClaimValues(userName, userClaims, null);
                if (log.isDebugEnabled()) {
                    log.debug("Successfully updated the user claims related to post authentication event.");
                }
            } catch (UserStoreException e) {
                throw new IdentityEventException(
                        "Error occurred while updating user claims related to post authentication event.", e);
            }
        }
    }

    private void handleCredentialUpdate(Map<String, Object> eventProperties, UserStoreManager userStoreManager)
            throws IdentityEventException {

        if (log.isDebugEnabled()) {
            log.debug("Start handling post credential update event.");
        }
        try {
            String username;
            if (eventProperties.containsKey(IdentityEventConstants.EventProperty.USER_NAME)) {
                username = (String) eventProperties.get(IdentityEventConstants.EventProperty.USER_NAME);
            } else {
                username = ((AbstractUserStoreManager) userStoreManager).getUserNameFromUserID(
                        (String) eventProperties.get(IdentityEventConstants.EventProperty.USER_ID));
            }
            String lastPasswordUpdateTime = Long.toString(System.currentTimeMillis());
            Map<String, String> userClaims = new HashMap<>();
            userClaims.put(IdentityMgtConstants.LAST_PASSWORD_UPDATE_TIME, lastPasswordUpdateTime);
            userStoreManager.setUserClaimValues(username, userClaims, null);
            if (log.isDebugEnabled()) {
                log.debug("Successfully updated the user claims related to post credential update event.");
            }
        } catch (UserStoreException e) {
            throw new IdentityEventException(
                    "Error occurred while updating user claims related to credential update event.", e);
        }
    }

    @Override
    public String getName() {

        return "authenticationFlowClaimUpdateHandler";
    }

    @Override
    public int getPriority(MessageContext messageContext) {

        return 50;
    }

    @Override
    public void init(InitConfig configuration) throws IdentityRuntimeException {

        super.init(configuration);
    }

    public String getFriendlyName() {

        return "Authentication Flow Claim Update Handler";
    }
}
