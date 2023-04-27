package com.security.user_security.utils;

import com.security.user_security.pojo.Code;
import com.security.user_security.pojo.User;
import lombok.Data;

/**
 * @Description: TODO
 * @Author: Kang
 * @CreateTime: 2023-04-01  22:44
 * @Version: 1.0
 */
@Data
public class UserDTO {
    private User user;
    private Code code;
}
