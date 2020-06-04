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

package org.wso2.carbon.identity.recovery.handler.function;

import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Converts a tenant-wise property to a ConfigurationManagement Resource attribute.
 */
public class PropertiesToResourceAdd {

    /**
     * Applies this function to the given argument.
     *
     * @param properties the function argument
     * @return the function result
     */
    public ResourceAdd apply(String featureId, Map<String, String> properties) {

        ResourceAdd resourceAdd = new ResourceAdd();
        resourceAdd.setName(featureId);
        List<Attribute> attributes = new ArrayList<>();

        properties.forEach((k, v) -> {
            Attribute attribute = new Attribute();
            attribute.setKey(k);
            attribute.setValue(v);
            attributes.add(attribute);
        });
        resourceAdd.setAttributes(attributes);
        return resourceAdd;
    }
}