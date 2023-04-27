package com.security.user_security.mapper;

import com.security.user_security.pojo.User;

import java.util.List;
import java.util.Map;

public interface UserMapper {

    void addUser(User user);

    User queryUserByPhoneWithPassword(String enphone, String enpassword);

    /**
     * description: 只修改username、password、idnumber、channel四个字段
     * @author: Kang
     * @param enUser: 加密后的用户对象
     * @return: void
     */
    void updateUserById(User enUser);

    /**
     * description: 按照条件（用户名、手机号、渠道）查询用户信息，map为空则查询所有数据
     * @author: Kang
     * @param map: (username、phone、channel)
     * @return: java.util.List<com.security.user_security.pojo.User>
     */
    List<User> selectUserForConditionByPage(Map<String,Object> map);

    List<User> selectUsersByIds(String[] id);

    /**
     * description: 根据id修改用户所有字段
     * @author: Kang
     * @param enUser: 加密后的用户对象
     * @return: void
     */
    void updateUser(User enUser);

    /**
     * description: 根据id查询用户加密信息并返回
     * @author: Kang
     * @param id: 用户id
     * @return: User
     */
    User selectUserById(String id);
}
