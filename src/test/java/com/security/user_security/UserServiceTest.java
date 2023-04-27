package com.security.user_security;

import cn.hutool.core.util.IdUtil;
import com.github.pagehelper.PageInfo;
import com.security.user_security.mapper.CodeMapper;
import com.security.user_security.mapper.UserMapper;
import com.security.user_security.pojo.Code;
import com.security.user_security.pojo.User;
import com.security.user_security.service.UserService;
import com.security.user_security.utils.SecurityUtil;
import com.security.user_security.utils.SystemConstant;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import javax.annotation.Resource;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @Description: TODO
 * @Author: Kang
 * @CreateTime: 2023-04-01  17:52
 * @Version: 1.0
 */
@SpringBootTest
public class UserServiceTest {

    @Resource
    UserService userService;

    @Resource
    UserMapper userMapper;

    @Resource
    CodeMapper codeMapper;



    @Test
    public void addUserTest(){
        User user = new User();
        user.setId(IdUtil.simpleUUID());
        user.setUsername("张三");
        user.setPassword("123456");
        user.setIdnumber("56456465456456");
        user.setPhone("15896885164");
        user.setChannel("微信");
        userMapper.addUser(user);
    }

    @Test
    public void addCodeTest(){
        Code code = new Code();
        code.setId(IdUtil.simpleUUID());
        code.setUsernameHash("张三");
        code.setPasswordHash("6646465");
        code.setIdnumberHash("1111111");
        code.setPhoneHash("22222222");
        codeMapper.addCode(code);
    }

    @Test
    public void encryptionTest(){
        User user = new User();
        user.setId(IdUtil.simpleUUID());
        user.setUsername("张三");
        user.setPassword("123456");
        user.setIdnumber("410522199904299432");
        user.setPhone("15896885164");
        user.setChannel("微信");
        userService.encryption(user);
    }

    @Test
    public void queryUserForConditionByPageTest(){
        Map<String, Object> map = new HashMap<>();
        int pageNum=1;
        int pageSize=2;
        String phone = "15896885122";
        String username = "李四";
        String channel = "QQ";
        String enUsername = SecurityUtil.encryptStr(username);
        String enphone = SecurityUtil.encryptStr(phone);
        map.put("username", enUsername);
        map.put("phone", enphone);
        map.put("channel", channel);
        PageInfo<User> pageInfo = userService.queryUserForConditionByPage(pageNum, pageSize, map);
        for (User user : pageInfo.getList()) {
            System.out.println(user);
        }
    }

    @Test
    public void queryUsersByIds(){
//        userService.queryUsersByIds()
    }

    @Test
    public void AESTest(){
        String[] id=new String[]{"04a3e71dfdc84811851cf44f633f400f","0c80464d5d3141d092c2ca017faa9b2a"};
        //得到解密后的用户信息
        List<User> users=userService.queryUsersByIds(id);
//        for (User user : users) {
//            System.out.println(user);
//        }
        //通过AES加密用户+RSA加密AES密钥
        String enUsersStr = userService.encryptionByAES(users);
        //解密
        List<User> userList = userService.decryptionByAES(enUsersStr, SystemConstant.PRIVATEKEY);
        for (User user : userList) {
//            System.out.println(user);
            System.err.println(user);
        }
    }

}
