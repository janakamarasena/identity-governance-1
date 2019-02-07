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

package org.wso2.carbon.identity.claim.verification.core.model;

public class ValidationResponse {

    // internal claim verification success or not
    private boolean isValid;

    // only sent when external verification is  needed
    private String code;

    public boolean isValid() {

        return isValid;
    }

    public void setValid(boolean valid) {

        isValid = valid;
    }

    public String getCode() {

        return code;
    }

    public void setCode(String code) {

        this.code = code;
    }
}
