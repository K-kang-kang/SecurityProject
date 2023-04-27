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
public class Code {

    private String id;
    private String usernameHash;
    private String passwordHash;
    private String idnumberHash;
    private String phoneHash;
}
