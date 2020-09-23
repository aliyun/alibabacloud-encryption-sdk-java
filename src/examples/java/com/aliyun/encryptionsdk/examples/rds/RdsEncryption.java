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

package com.aliyun.encryptionsdk.examples.rds;

import com.aliyun.encryptionsdk.AliyunCrypto;
import com.aliyun.encryptionsdk.AliyunConfig;
import com.aliyun.encryptionsdk.provider.dataKey.AbstractExternalStoreDataKeyProvider;
import com.aliyun.encryptionsdk.provider.dataKey.SecretManagerDataKeyProvider;

import java.util.Base64;
import java.util.Collections;
import java.util.Map;

public class RdsEncryption {

    private static final String KEY_ID = "acs:kms:RegionId:UserId:key/CmkId";
    private static final AliyunCrypto SDK;
    static {
        AliyunConfig config = new AliyunConfig();
        config.withAccessKey("<AccessKeyId>", "<AccessKeySecret>");
        SDK = new AliyunCrypto(config);
    }

    public static void main(String[] args) {
        //加密上下文
        Map<String, String> encryptionContext = Collections.singletonMap("encryption", "context");
        //待加密数据
        Data data = new Data("Tom", 20);

        //1.解析待加密数据的类
        FieldModel<Data> fieldModel = new FieldModel<>(Data.class);

        //======================加密流程===========================
        //2.遍历有RdsColumn注解的属性
        fieldModel.getMap().forEach((key, bean) -> {
            //3.利用反射将一个需要加密的属性从待加密数据中读出
            Object object = bean.getReflect().get(data);
            //4.创建provider，该provider需要为AbstractExternalStoreDataKeyProvider实现
            //（key为RdsColumn注解的dataKeyTag，标识一个数据密钥）
            AbstractExternalStoreDataKeyProvider provider = new SecretManagerDataKeyProvider(KEY_ID, key);
            //5.进行加密操作（加密数据需要进行类型转换）
            byte[] encryptResult = SDK.encrypt(provider, TypeConvert.convertToBytes(object), encryptionContext).getResult();
            //6.将密文存入RdsColumn注解的encryptedName所指定的属性
            bean.getEncryptedBean().getReflect().set(data, encryptResult);
        });
        //完成加密操作
        System.out.println("Encryption complete: " + data.toString());

        //将明文设置为空
        data.setName("");
        data.setAge(-1);

        //======================解密流程===========================
        //遍历有RdsColumn注解的属性
        fieldModel.getMap().forEach((key, bean) -> {
            //利用反射从RdsColumn注解的encryptedName所指定的属性里读取出密文
            Object object = bean.getEncryptedBean().getReflect().get(data);
            //创建provider，该provider需要为AbstractExternalStoreDataKeyProvider实现
            //（key为RdsColumn注解的dataKeyTag，标识一个数据密钥）
            AbstractExternalStoreDataKeyProvider provider = new SecretManagerDataKeyProvider(KEY_ID, key);
            //进行解密操作
            byte[] decryptResult = SDK.decrypt(provider, (byte[]) object).getResult();
            //将明文存入RdsColumn注解的属性（得到的明文需要进行类型转换）
            bean.getReflect().set(data, TypeConvert.convertToObject(decryptResult, bean.getReturnType()));
        });
        //完成解密操作
        System.out.println("Decryption complete: " + data.toString());
    }

    @RdsTable(tableName = "table")
    public static final class Data {
        @RdsColumn(encryptedName = "encryptedName", dataKeyTag = "name")
        private String name;
        private byte[] encryptedName;
        @RdsColumn(encryptedName = "encryptedAge", dataKeyTag = "age")
        private int age;
        private byte[] encryptedAge;

        public Data(String name, int age) {
            this.name = name;
            this.age = age;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public byte[] getEncryptedName() {
            return encryptedName;
        }

        public void setEncryptedName(byte[] encryptedName) {
            this.encryptedName = encryptedName;
        }

        public int getAge() {
            return age;
        }

        public void setAge(int age) {
            this.age = age;
        }

        public byte[] getEncryptedAge() {
            return encryptedAge;
        }

        public void setEncryptedAge(byte[] encryptedAge) {
            this.encryptedAge = encryptedAge;
        }

        @Override
        public String toString() {
            return "Data{" +
                    "name=" + name +
                    ", encryptedName=" + Base64.getEncoder().encodeToString(encryptedName) +
                    ", age=" + age +
                    ", encryptedAge=" + Base64.getEncoder().encodeToString(encryptedAge) +
                    "}";
        }
    }
}
