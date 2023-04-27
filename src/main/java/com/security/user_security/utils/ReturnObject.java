package com.security.user_security.utils;

/**
 * @Description:
 * @Author: Kang
 * @Version: 1.0
 */
public class ReturnObject {

    private String code;
    private String message;
    private Object retData; //其他数据

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public Object getRetData() {
        return retData;
    }

    public void setRetData(Object retData) {
        this.retData = retData;
    }
}
