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

import com.aliyun.encryptionsdk.exception.AliyunException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class FieldModel<T> {
    private String tableName;
    private Map<String, Bean<T>> map = new ConcurrentHashMap<>();

    public FieldModel(Class<T> clazz) {
        putAll(clazz);
    }

    public String getTableName() {
        return tableName;
    }

    public Map<String, Bean<T>> getMap() {
        return map;
    }

    private void putAll(Class<T> clazz) {
        processTable(clazz);
        for (Field field: clazz.getDeclaredFields()) {
            //判断属性是否需要做处理
            if (isProcessField(field)) {
                RdsColumn column = field.getAnnotation(RdsColumn.class);
                //获取保存加密信息的属性
                Bean<T> encryptedBean = processEncryptedBean(clazz, column.encryptedName());
                //获取需要加密的属性
                Bean<T> bean = new Bean<>(field, column, encryptedBean);
                //以RdsColumn注解的dataKeyTag为key，保存属性信息
                map.put(bean.getColumn().dataKeyTag(), bean);
            }
        }
    }

    private Bean<T> processEncryptedBean(Class<T> clazz, String name) {
        Field field;
        try {
            field = clazz.getDeclaredField(name);
        } catch (NoSuchFieldException e) {
            throw new AliyunException(e);
        }
       return new Bean<>(field, null, null);
    }

    private void processTable(Class<T> clazz) {
        RdsTable table = clazz.getAnnotation(RdsTable.class);
        if (table == null) {
            throw new AliyunException("RdsTable not obtained");
        }
        tableName = table.tableName();
    }

    private boolean isProcessField(Field field) {
        Annotation ignore = field.getAnnotation(RdsIgnore.class);
        if (ignore != null) {
            return false;
        }
        Annotation column = field.getAnnotation(RdsColumn.class);
        return column != null;
    }

    public static class Bean<T> {
        private MethodReflect<T> reflect;
        private RdsColumn column;
        private Bean<T> encryptedBean;
        private Type returnType;

        public Bean(Field field, RdsColumn column, Bean<T> encryptedBean) {
            this.reflect = new MethodReflect<>(field);
            this.column = column;
            this.encryptedBean = encryptedBean;
            if (encryptedBean != null) {
                this.returnType = reflect.getter.getReturnType();
            }
        }

        public MethodReflect<T> getReflect() {
            return reflect;
        }

        public RdsColumn getColumn() {
            return column;
        }

        public Bean<T> getEncryptedBean() {
            return encryptedBean;
        }

        public Type getReturnType() {
            return returnType;
        }
    }

    public static class MethodReflect<T> {
        private Method getter;
        private Method setter;

        private MethodReflect(Field field) {
            this.getter = getterMethod(field);
            this.setter = setterMethod(field);
        }

        public Object get(T object) {
            try {
                return getter.invoke(object);
            } catch (final Exception e) {
                throw new AliyunException("could not invoke getter method on " + object.getClass(), e);
            }
        }

        public void set(T object, Object value) {
            try {
                setter.invoke(object, value);
            } catch (final Exception e) {
                throw new AliyunException("could not invoke setter method on " + object.getClass(), e);
            }
        }

        private Method getterMethod(Field field) {
            String fieldName = field.getName();
            String name = "get" + fieldName.substring(0,1).toUpperCase()+fieldName.substring(1);
            try {
                return field.getDeclaringClass().getMethod(name);
            } catch (NoSuchMethodException e) {
            }
            return null;
        }

        private Method setterMethod(Field field) {
            String fieldName = field.getName();
            String name = "set" + fieldName.substring(0,1).toUpperCase()+fieldName.substring(1);
            try {
                return field.getDeclaringClass().getMethod(name, getter.getReturnType());
            } catch (NoSuchMethodException e) {
            }
            return null;
        }
    }
}
