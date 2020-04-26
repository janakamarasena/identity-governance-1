/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
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

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.event.IdentityEventClientException;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.IdentityEventServerException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.recovery.IdentityRecoveryClientException;
import org.wso2.carbon.identity.recovery.IdentityRecoveryConstants;
import org.wso2.carbon.identity.recovery.IdentityRecoveryServerException;
import org.wso2.carbon.identity.recovery.model.UserChallengeAnswer;
import org.wso2.carbon.identity.recovery.util.Utils;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreManager;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ChallengeAnswerValidationHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(ChallengeAnswerValidationHandler.class);

    public String getName() {
        return "challengeAnswerValidation";
    }

    @Override
    public int getPriority(MessageContext messageContext) {
        return 50;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        String eventName = event.getEventName();
        Map<String, Object> eventProperties = event.getEventProperties();
        String userName = (String) eventProperties.get(IdentityEventConstants.EventProperty.USER_NAME);
        UserStoreManager userStoreManager = (UserStoreManager) eventProperties.
                get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER);
        String tenantDomain = (String) eventProperties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);
        String domainName = userStoreManager.getRealmConfiguration().
                getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
        UserChallengeAnswer[] userChallengeAnswers = (UserChallengeAnswer[]) eventProperties.
                get(IdentityEventConstants.EventProperty.USER_CHALLENGE_ANSWERS);

        User user = new User();
        user.setUserName(userName);
        user.setTenantDomain(tenantDomain);
        user.setUserStoreDomain(domainName);

        if (IdentityEventConstants.Event.PRE_SET_CHALLENGE_QUESTION_ANSWERS.equals(eventName)) {
            try {
                preSetChallengeQuestionAnswers(user, userChallengeAnswers);
            } catch (IdentityRecoveryClientException e) {
                throw new IdentityEventClientException(e.getErrorCode(), e.getMessage(), e);
            } catch (IdentityRecoveryServerException e) {
                throw new IdentityEventServerException(e.getErrorCode(), e.getMessage(), e);
            }
        }

        if (IdentityEventConstants.Event.POST_SET_CHALLENGE_QUESTION_ANSWERS.equals(eventName)) {
            postSetChallengeQuestionAnswers(user, userChallengeAnswers);
        }
    }

    private void preSetChallengeQuestionAnswers(User user, UserChallengeAnswer[] userChallengeAnswers)
            throws IdentityEventException, IdentityRecoveryClientException, IdentityRecoveryServerException {

        UserChallengeAnswer[] existingChallengeAnswers = getExistingChallengeAnswers(user, userChallengeAnswers);
        UserChallengeAnswer[] newChallengeAnswers = getNewChallengeAnswers(userChallengeAnswers,
                existingChallengeAnswers);
        validateChallengeQuestionAnswer(user.getTenantDomain(), newChallengeAnswers);
        if (Boolean.parseBoolean(Utils.getConnectorConfig(IdentityRecoveryConstants.ConnectorConfig.
                CHALLENGE_QUESTION_ANSWER_UNIQUENESS, user.getTenantDomain()))){
            if (!validateUniquenessOfAnswer(newChallengeAnswers, existingChallengeAnswers)) {
                if (log.isDebugEnabled()) {
                    log.debug("The challenge question answer is not unique. " +
                            "The given challenge question answer has been used more than once");
                }
                throw Utils.handleClientException (
                        IdentityRecoveryConstants.ErrorMessages.ERROR_CODE_NOT_UNIQUE_ANSWER, null);
            }
        }
    }

    private void postSetChallengeQuestionAnswers(User user, UserChallengeAnswer[] userChallengeAnswers) {
    }

    /**
     * Filter existing hashed challenge question answers from user added challenge question answers.
     */
    private UserChallengeAnswer[] getExistingChallengeAnswers (User user, UserChallengeAnswer[] userChallengeAnswers)
            throws IdentityRecoveryServerException {

        List<UserChallengeAnswer> existingChallengeAnswers = new ArrayList<>();
        if (!ArrayUtils.isEmpty(userChallengeAnswers)) {
            for (UserChallengeAnswer userChallengeAnswer : userChallengeAnswers) {
                if (userChallengeAnswer.getQuestion().getQuestionSetId() != null &&
                        userChallengeAnswer.getQuestion().getQuestion() != null &&
                        userChallengeAnswer.getAnswer() != null) {
                    try {
                        String oldValue = Utils.
                                getClaimFromUserStoreManager(user, userChallengeAnswer.getQuestion().
                                        getQuestionSetId().trim());
                        if (oldValue != null && oldValue.
                                contains(IdentityRecoveryConstants.DEFAULT_CHALLENGE_QUESTION_SEPARATOR)) {
                            String oldAnswer = oldValue.
                                    split(IdentityRecoveryConstants.DEFAULT_CHALLENGE_QUESTION_SEPARATOR)[1];
                            if (oldAnswer.trim().equals(userChallengeAnswer.getAnswer().trim())) {
                                existingChallengeAnswers.add(userChallengeAnswer);
                            }
                        }
                    } catch (org.wso2.carbon.user.api.UserStoreException e) {
                        throw Utils.handleServerException(IdentityRecoveryConstants.ErrorMessages.
                                ERROR_CODE_GETTING_CLAIM_VALUES, user.getUserName(), e);
                    }
                }
            }
        }
        UserChallengeAnswer[] existingAnswers = new UserChallengeAnswer[existingChallengeAnswers.size()];
        return existingChallengeAnswers.toArray(existingAnswers);
    }

    /**
     * Filter new challenge question answers in plain text from user added challenge question answers.
     */
    private UserChallengeAnswer[] getNewChallengeAnswers (UserChallengeAnswer[] userChallengeAnswers,
                                                          UserChallengeAnswer[] existingChallengeAnswers) {

        List<UserChallengeAnswer> challengeAnswers =
                new ArrayList<>(Arrays.asList(userChallengeAnswers));
        List<UserChallengeAnswer> oldChallengeAnswers =
                new ArrayList<>(Arrays.asList(existingChallengeAnswers));
        List<UserChallengeAnswer> newChallengeAnswers = new ArrayList<>(challengeAnswers);
        for (UserChallengeAnswer userChallengeAnswer : challengeAnswers) {
            for (UserChallengeAnswer oldUserChallengeAnswer : oldChallengeAnswers) {
                if (userChallengeAnswer.getAnswer().trim().equals(oldUserChallengeAnswer.getAnswer().trim())) {
                    newChallengeAnswers.remove(userChallengeAnswer);
                }
            }
        }
        UserChallengeAnswer[] newAnswers = new UserChallengeAnswer[newChallengeAnswers.size()];
        return newChallengeAnswers.toArray(newAnswers);
    }

    /**
     * Validate challenge question answers according to configured regex pattern.
     */
    private void validateChallengeQuestionAnswer(String tenantDomain, UserChallengeAnswer[] newChallengeAnswers)
            throws IdentityEventException, IdentityRecoveryClientException {

        for (UserChallengeAnswer userChallengeAnswer : newChallengeAnswers) {
            if (userChallengeAnswer.getAnswer().trim().
                    matches(Utils.getConnectorConfig(IdentityRecoveryConstants.ConnectorConfig.
                            CHALLENGE_QUESTION_ANSWER_REGEX, tenantDomain))) {
                if (log.isDebugEnabled()) {
                    log.debug("The challenge question answer is in the expected format");
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("The challenge question answer is not in the expected format. " +
                            "The answer should only contain the alphanumeric characters");
                }
                throw Utils.handleClientException (
                        IdentityRecoveryConstants.ErrorMessages.ERROR_CODE_INVALID_ANSWER_FORMAT, null);
            }
        }
    }

    /**
     * Validate the uniqueness of a given answer.
     */
    private boolean validateUniquenessOfAnswer(UserChallengeAnswer[] newChallengeAnswers,
                                               UserChallengeAnswer[] existingChallengeAnswers)
            throws IdentityRecoveryServerException {

        List<String> hashedChallengeAnswers = new ArrayList<>();
        for (UserChallengeAnswer userChallengeAnswer : newChallengeAnswers) {
            try {
                hashedChallengeAnswers.add(Utils.doHash(userChallengeAnswer.getAnswer().trim().toLowerCase()));
            } catch (UserStoreException e) {
                throw Utils.handleServerException(
                        IdentityRecoveryConstants.ErrorMessages.ERROR_CODE_HASH_CHALLENGE_ANSWER, null);
            }
        }
        for (UserChallengeAnswer existingChallengeAnswer : existingChallengeAnswers) {
            hashedChallengeAnswers.add(existingChallengeAnswer.getAnswer().trim());
        }

        Set<String> uniqueChallengeAnswerHashSet = new HashSet<>();
        for (String userChallengeAnswer : hashedChallengeAnswers) {
            uniqueChallengeAnswerHashSet.add(userChallengeAnswer.trim());
        }

        // If all elements are distinct, size of the uniqueChallengeAnswerHashSet should be same to the summation
        // of the lengths of newChallengeAnswers array and existingChallengeAnswers array.
        return (uniqueChallengeAnswerHashSet.size() == (newChallengeAnswers.length + existingChallengeAnswers.length));
    }
}
