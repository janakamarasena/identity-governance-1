/*
 *  Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.claim.verification.core.internal;

import org.wso2.carbon.identity.claim.verification.core.verifier.ClaimVerifier;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.ArrayList;
import java.util.List;

public class ClaimVerificationServiceDataHolder {
    private static ClaimVerificationServiceDataHolder instance = new ClaimVerificationServiceDataHolder(); // volatile??
    private List<ClaimVerifier> claimVerifiers = new ArrayList<>();
    private IdentityEventService identityEventService;
    private RealmService realmService;

    public static ClaimVerificationServiceDataHolder getInstance() {
        return instance;
    }

    public List<ClaimVerifier> getClaimVerifiers() {

        return claimVerifiers;
    }

    public void setClaimVerifiers(List<ClaimVerifier> claimVerifiers) {

        this.claimVerifiers = claimVerifiers;
    }

    public IdentityEventService getIdentityEventService() {
        return identityEventService;
    }

    public void setIdentityEventService(IdentityEventService identityEventService) {
        this.identityEventService = identityEventService;
    }

    public void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }

    public RealmService getRealmService() {
        return realmService;
    }
}
