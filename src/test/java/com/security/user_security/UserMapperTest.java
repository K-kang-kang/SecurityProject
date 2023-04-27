package com.security.user_security;

import com.security.user_security.mapper.CodeMapper;
import com.security.user_security.mapper.UserMapper;
import com.security.user_security.pojo.Code;
import com.security.user_security.pojo.User;
import com.security.user_security.utils.SecurityUtil;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import javax.annotation.Resource;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @Description:
 * @Author: Kang
 * @Version: 1.0
 */
@SpringBootTest
public class UserMapperTest {

    @Resource
    private UserMapper userMapper;

    @Resource
    private CodeMapper codeMapper;

    @Test
    public void selectUserForConditionByPageTest() {
        Map<String, Object> map = new HashMap<>();
        String phone = "15896885122";
        String username = "李四";
        String channel = "QQ";
        String enUsername = SecurityUtil.encryptStr(username);
        String enphone = SecurityUtil.encryptStr(phone);
        map.put("username", enUsername);
        map.put("phone", enphone);
        map.put("channel", channel);
        List<User> users = userMapper.selectUserForConditionByPage(map);
        for (User user : users) {
            Code code = codeMapper.selectCodeById(user.getId());
            System.out.println(user);
            System.out.println(code);
        }
    }
}
