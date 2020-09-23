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

package com.aliyun.encryptionsdk.model.test;

import com.aliyun.encryptionsdk.model.CmkId;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class CmkIdTest {
    private static final String KEY_ID = "acs:kms:RegionId:UserId:key/CmkId";
    @Test
    public void testCmkIdConstructor(){
        CmkId cmkId = new CmkId(KEY_ID);
        assertTrue(cmkId.isArn());
        assertEquals("cn-hangzhou", cmkId.getRegion());
        assertEquals(KEY_ID, cmkId.getKeyId());
        assertEquals("CmkId", cmkId.getRawKeyId());
    }

}
