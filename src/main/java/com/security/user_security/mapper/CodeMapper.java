package com.security.user_security.mapper;

import com.security.user_security.pojo.Code;
import com.security.user_security.pojo.User;

public interface CodeMapper {

    void addCode(Code code);

    Code isNotExistByPhoneCode(String phoneCode);

    Code queryCodeByPhoneWithPassword(String phoneCode, String passwordCode);

    /**
     * description: 只修改username_hash、password_hash、idnumber_hash三个字段
     * @author: Kang
     * @param code: 用户消息码对象
     * @return: void
     */
    void updateCodeById(Code code);

    Code selectCodeById(String id);

    /**
     * description: 根据id修改用户消息码表所有字段
     * @author: Kang
     * @param code: 用户消息码对象
     * @return: void
     */
    void updateCode(Code code);
}
