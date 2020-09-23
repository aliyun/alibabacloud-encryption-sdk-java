/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.aliyun.encryptionsdk.model;

import com.aliyun.encryptionsdk.exception.InvalidArgumentException;
import com.aliyuncs.utils.StringUtils;

import java.util.Objects;

public class CmkId {
    public static final String PREFIX = "acs:";

    private String keyId;
    private String region;
    private String rawKeyId;
    private boolean isArn = false;

    public CmkId(String keyId) {
        if (StringUtils.isEmpty(keyId)) {
            throw new InvalidArgumentException("keyId cannot be empty");
        }
        this.keyId = keyId;
        if (keyId.startsWith(PREFIX)) {
            parsingKeyId(keyId);
        }
        //TODO:如果keyId不是arn，是cmk或alias的时候需要指定region id，二期考虑是否支持
        //else {
            //this.rawKeyId = keyId;
            //this.region = regionId;
        //}
    }

    public String getKeyId() {
        return keyId;
    }

    public String getRegion() {
        return region;
    }

    public String getRawKeyId(){
        return rawKeyId;
    }

    public boolean isArn() {
        return isArn;
    }

    private void parsingKeyId(String keyId) {
        String[] strArr = keyId.split(":");
        if (strArr.length != 5) {
            throw new InvalidArgumentException("ARN parsing error, ARN format would be 'acs:kms:<region>:<uid>:key/<cmkid>'");
        }

        if (!"acs".equals(strArr[0])) {
            throw new InvalidArgumentException("ARN must start with 'acs:'");
        }
        if (!"kms".equals(strArr[1])) {
            throw new InvalidArgumentException("ARN must specify service");
        }
        if (StringUtils.isEmpty(strArr[2])) {
            throw new InvalidArgumentException("ARN must specify region");
        }
        if (StringUtils.isEmpty(strArr[3])) {
            throw new InvalidArgumentException("ARN must specify user id");
        }
        if (StringUtils.isEmpty(strArr[4])) {
            throw new InvalidArgumentException("ARN must specify resource");
        }
        if (!strArr[4].startsWith("key/")) {
            throw new InvalidArgumentException("ARN resource type must be 'key'");
        }

        this.region = strArr[2];
        this.rawKeyId = strArr[4].substring(strArr[4].indexOf("/") + 1);
        this.isArn = true;
    }

    public boolean isCommonRegion(CmkId cmkId) {
        if (!StringUtils.isEmpty(region) && !StringUtils.isEmpty(cmkId.getRegion())) {
            return region.equalsIgnoreCase(cmkId.getRegion());
        }
        return false;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        CmkId cmkId = (CmkId) o;
        return keyId.equals(cmkId.keyId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(keyId);
    }
}
