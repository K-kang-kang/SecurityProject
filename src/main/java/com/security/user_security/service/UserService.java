package com.security.user_security.service;

import com.github.pagehelper.PageInfo;
import com.security.user_security.pojo.Code;
import com.security.user_security.pojo.User;
import com.security.user_security.utils.UserDTO;

import java.util.List;
import java.util.Map;

public interface UserService {
    boolean verification(User user);

    /**
     * description: 加密User，并将用户加密信息存入用户表，用户消息码信息存入用户消息码表;
     * 根据用户id查询用户表和用户消息码表
     * 如果用户不为空，则根据id修改用户表和用户消息码表中所有的信息;
     * 如果用户为空，则生成id，并将加密后的用户信息保存至用户表，用户消息认证码保存至用户消息认证码表;
     * 消息码操作同上用户的操作
     * @author: Kang
     * @param user: 要加密的用户信息
     * @return: void
     */
    void encryption(User user);

    /**
     * description: 解密
     * @author: Kang
     * @param enUser: 加密后的用户信息
     * @param code:  用户消息认证码
     * @return: 解密后的用户
     */
    User decryption(User enUser,Code code);

    /**
     * description: 根据手机号和密码查询用户的加密信息以及用户消息认证码，返回用户密文以及用户消息认证码
     * @author: Kang
     * @param phone:
     * @param password:
     * @return: com.security.user_security.utils.UserDTO
     */
    UserDTO queryUserAndCodeByPhoneWithPassword(String phone, String password);

    void editUserById(User user);

    /**
     * description: 按照条件查询解密后的用户信息，三个条件(用户名、手机号、了解渠道)为空时，返回所有用户解密后的信息
     * @author: Kang
     * @param pageNum: 页码
     * @param pageSize: 每页显示条数
     * @param map: 条件搜索框的三个条件，可为空
     * @return: com.github.pagehelper.PageInfo<com.security.user_security.pojo.User>
     */
    PageInfo<User> queryUserForConditionByPage(int pageNum, int pageSize, Map<String, Object> map);

    /**
     * description: 根据id数组返回解密后的用户信息
     * @author: Kang
     * @param id:用户id
     * @return: java.util.List<com.security.user_security.pojo.User>
     */
    List<User> queryUsersByIds(String[] id);

    /**
     * description: 通过AES算法加密用户列表中的用户信息，返回用户密文字符串+RSA加密后的AES密钥拼合的字符串
     * @author: Kang
     * @param users: 用户(明文)列表
     * @return: java.lang.String
     */
    String encryptionByAES(List<User> users);

    /**
     * description: 将密文解析为用户密文和密钥密文，通过私钥解密密钥密文，再用解密的密钥通过AES算法解密用户密文，返回解密后的用户集合
     * @author: Kang
     * @param encryptionStr: 要解密的密文
     * @param privateKey: 私钥
     * @return: java.util.List<com.security.user_security.pojo.User>
     */
    List<User> decryptionByAES(String encryptionStr,String privateKey);
}
