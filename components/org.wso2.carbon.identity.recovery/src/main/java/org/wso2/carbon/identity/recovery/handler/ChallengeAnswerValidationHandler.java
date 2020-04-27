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
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.util.IdentityUtil;
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

/**
 * This class is used to validate the challenge question answers.
 */
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
        UserStoreManager userStoreManager = (UserStoreManager) eventProperties.
                get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER);
        UserChallengeAnswer[] userChallengeAnswers = (UserChallengeAnswer[]) eventProperties.
                get(IdentityEventConstants.EventProperty.USER_CHALLENGE_ANSWERS);

        User user = new User();
        user.setUserName((String) eventProperties.get(IdentityEventConstants.EventProperty.USER_NAME));
        user.setTenantDomain((String) eventProperties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN));
        user.setUserStoreDomain(userStoreManager.getRealmConfiguration().
                getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME));

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
                CHALLENGE_QUESTION_ANSWER_UNIQUENESS_ENABLE, user.getTenantDomain()))) {
            validateUniquenessOfAnswer(newChallengeAnswers, existingChallengeAnswers);
        }
    }

    private void postSetChallengeQuestionAnswers(User user, UserChallengeAnswer[] userChallengeAnswers) {
        // This method is not implemented.
    }

    /**
     * Filter existing hashed challenge question answers from user added challenge question answers.
     *
     * @param user                 User
     * @param userChallengeAnswers Array of all user challenge answers
     * @return Array of existing user challenge answers
     * @throws IdentityRecoveryServerException Error while getting the claim values.
     */
    private UserChallengeAnswer[] getExistingChallengeAnswers(User user, UserChallengeAnswer[] userChallengeAnswers)
            throws IdentityRecoveryServerException {

        List<UserChallengeAnswer> existingChallengeAnswers = new ArrayList<>();
        if (!ArrayUtils.isEmpty(userChallengeAnswers)) {
            for (UserChallengeAnswer userChallengeAnswer : userChallengeAnswers) {
                if (userChallengeAnswer.getQuestion().getQuestionSetId() != null &&
                        userChallengeAnswer.getQuestion().getQuestion() != null &&
                        userChallengeAnswer.getAnswer() != null) {
                    try {
                        String previousValue = Utils.getClaimFromUserStoreManager(user, userChallengeAnswer.getQuestion().
                                getQuestionSetId().trim());
                        String separator = IdentityUtil.getProperty(IdentityRecoveryConstants.ConnectorConfig
                                .QUESTION_CHALLENGE_SEPARATOR);
                        if (StringUtils.isNotBlank(previousValue) && previousValue.contains(separator)) {
                            String previousAnswer = previousValue.split(separator)[1];
                            if (previousAnswer.trim().equals(userChallengeAnswer.getAnswer().trim())) {
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
     *
     * @param userChallengeAnswers     Array of all challenge answers
     * @param existingChallengeAnswers Array of existing stored challenge answers
     * @return Array of newly added challenge answers.
     */
    private UserChallengeAnswer[] getNewChallengeAnswers(UserChallengeAnswer[] userChallengeAnswers,
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
     *
     * @param tenantDomain        Tenant Domain
     * @param newChallengeAnswers Newly added challenge question answers
     * @throws IdentityEventException          Error while reading the configurations
     * @throws IdentityRecoveryClientException Error while validating the answer regex.
     */
    private void validateChallengeQuestionAnswer(String tenantDomain, UserChallengeAnswer[] newChallengeAnswers)
            throws IdentityRecoveryClientException, IdentityEventException {

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
                throw Utils.handleClientException(
                        IdentityRecoveryConstants.ErrorMessages.ERROR_CODE_INVALID_ANSWER_FORMAT,
                        userChallengeAnswer.getAnswer());
            }
        }
    }

    /**
     * Validate the uniqueness of a given answer.
     *
     * @param newChallengeAnswers      Newly added challenge question answers
     * @param existingChallengeAnswers Existing challenge question answers
     * @throws IdentityRecoveryServerException Error while hashing the newly added answers
     * @throws IdentityRecoveryClientException Error while validating the answer uniqueness.
     */
    private void validateUniquenessOfAnswer(UserChallengeAnswer[] newChallengeAnswers,
                                            UserChallengeAnswer[] existingChallengeAnswers)
            throws IdentityRecoveryServerException, IdentityRecoveryClientException {

        Set<String> uniqueChallengeAnswerHashSet = new HashSet<>();
        for (UserChallengeAnswer existingChallengeAnswer : existingChallengeAnswers) {
            uniqueChallengeAnswerHashSet.add(existingChallengeAnswer.getAnswer().trim());
        }

        String hashedNewChallengeAnswer;
        for (UserChallengeAnswer userChallengeAnswer : newChallengeAnswers) {
            try {
                hashedNewChallengeAnswer = Utils.doHash(userChallengeAnswer.getAnswer().trim().toLowerCase());
            } catch (UserStoreException e) {
                throw Utils.handleServerException(
                        IdentityRecoveryConstants.ErrorMessages.ERROR_CODE_HASH_CHALLENGE_ANSWER, null);
            }
            if (!uniqueChallengeAnswerHashSet.add(hashedNewChallengeAnswer)) {
                if (log.isDebugEnabled()) {
                    log.debug("The challenge question answer is not unique. " +
                            "The given challenge question answer has been used more than once");
                }
                throw Utils.handleClientException(
                        IdentityRecoveryConstants.ErrorMessages.ERROR_CODE_NOT_UNIQUE_ANSWER,
                        userChallengeAnswer.getAnswer());
            }
        }
    }
}
