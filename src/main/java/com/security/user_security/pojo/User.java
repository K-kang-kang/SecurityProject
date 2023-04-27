package com.security.user_security.pojo;

import lombok.Data;
import lombok.ToString;

/**
 * @Description:
 * @Author: Kang
 * @Version: 1.0
 */
@Data
@ToString
public class User {

    private String id;
    private String username;
    private String password;
    private String permission;
    private String idnumber;
    private String phone;
    private String channel;


}
