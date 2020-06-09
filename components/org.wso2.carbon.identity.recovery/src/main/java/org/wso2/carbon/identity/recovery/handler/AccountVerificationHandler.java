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
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.IdentityEventServerException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.recovery.IdentityRecoveryConstants;
import org.wso2.carbon.identity.recovery.IdentityRecoveryServerException;
import org.wso2.carbon.identity.recovery.util.Utils;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * This class is used to verify the user account upon successful code confirmation.
 */
public class AccountVerificationHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(AccountVerificationHandler.class);

    public String getName() {

        return "UserAccountVerification";
    }

    @Override
    public int getPriority(MessageContext messageContext) {

        return 50;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        String eventName = event.getEventName();
        if (log.isDebugEnabled()) {
            log.debug("Handling event: " + eventName);
        }
        Map<String, Object> eventProperties = event.getEventProperties();
        Map<String, String> userClaims =
                (Map<String, String>) eventProperties.get(IdentityEventConstants.EventProperty.USER_CLAIMS);
        UserStoreManager userStoreManager =
                (UserStoreManager) eventProperties.get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER);
        User user = (User) eventProperties.get(IdentityEventConstants.EventProperty.USER);

        boolean accountLocked =
                Boolean.parseBoolean(userClaims.get(IdentityRecoveryConstants.ACCOUNT_LOCKED_CLAIM));
        if (!accountLocked) {
            Map<String, String> verifiedTimeClaim = new HashMap<>();
            verifiedTimeClaim.put(IdentityRecoveryConstants.ACCOUNT_VERIFIED_TIME_CLAIM, Instant.now().toString());
            try {
                updateUserClaim(user, userStoreManager, verifiedTimeClaim);
            } catch (IdentityRecoveryServerException e) {
                throw new IdentityEventServerException(e.getErrorCode(), e.getMessage(), e);
            }
        }
    }

    private void updateUserClaim(User user, UserStoreManager userStoreManager, Map<String, String> claim)
            throws IdentityRecoveryServerException {

        try {
            userStoreManager
                    .setUserClaimValues(IdentityUtil.addDomainToName(user.getUserName(), user.getUserStoreDomain()),
                            claim, null);
        } catch (UserStoreException e) {
            throw Utils.handleServerException(IdentityRecoveryConstants.ErrorMessages.ERROR_CODE_UNLOCK_USER_USER,
                    user.getUserName(), e);
        }

    }
}
