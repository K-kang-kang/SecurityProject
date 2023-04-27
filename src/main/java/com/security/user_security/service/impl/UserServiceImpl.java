package com.security.user_security.service.impl;

import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.symmetric.SymmetricAlgorithm;
import com.github.pagehelper.PageHelper;
import com.github.pagehelper.PageInfo;
import com.security.user_security.mapper.CodeMapper;
import com.security.user_security.mapper.UserMapper;
import com.security.user_security.pojo.Code;
import com.security.user_security.pojo.User;
import com.security.user_security.service.UserService;
import com.security.user_security.utils.SecurityUtil;
import com.security.user_security.utils.SystemConstant;
import com.security.user_security.utils.UserDTO;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.security.Key;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * @Description:
 * @Author: Kang
 * @Version: 1.0
 */
@Service
public class UserServiceImpl implements UserService {


    @Resource
    UserMapper userMapper;

    @Resource
    CodeMapper codeMapper;


    @Override
    public boolean verification(User user) {
        String phoneCode = SecurityUtil.hmacSm3(user.getPhone(), SystemConstant.KEY);
        Code isExist = codeMapper.isNotExistByPhoneCode(phoneCode);
        if (isExist != null) {
            return true;
        }
        return false;
    }

    @Override
    public User decryption(User enUser, Code code) {
        if (enUser == null || code == null) {
            return null;
        }
        User user = SecurityUtil.decryption(enUser, code);
        return user;
    }

    @Override
    public void encryption(User user) {
        UserDTO userDTO = SecurityUtil.encryption(user);
        if (userMapper.selectUserById(user.getId()) != null) {
            userMapper.updateUser(userDTO.getUser());
        } else {
            userMapper.addUser(userDTO.getUser());
        }
        if (codeMapper.selectCodeById(user.getId()) != null) {
            codeMapper.updateCode(userDTO.getCode());
        }else {
            codeMapper.addCode(userDTO.getCode());
        }


    }


    @Override
    public UserDTO queryUserAndCodeByPhoneWithPassword(String phone, String password) {
        String phoneCode = SecurityUtil.hmacSm3(phone, SystemConstant.KEY);
        String enphone = SecurityUtil.encryption(phone, phoneCode);
        String passwordCode = SecurityUtil.hmacSm3(password, SystemConstant.KEY);
        String enpassword = SecurityUtil.encryption(password, passwordCode);
        Code code = codeMapper.queryCodeByPhoneWithPassword(phoneCode, passwordCode);
        User user = userMapper.queryUserByPhoneWithPassword(enphone, enpassword);
        UserDTO userDTO = new UserDTO();
        userDTO.setUser(user);
        userDTO.setCode(code);
        return userDTO;
    }

    @Override
    public void editUserById(User user) {
        String usernameCode = SecurityUtil.hmacSm3(user.getUsername(), SystemConstant.KEY);
        String enUsername = SecurityUtil.encryption(user.getUsername(), usernameCode);
        String passwordCode = SecurityUtil.hmacSm3(user.getPassword(), SystemConstant.KEY);
        String enPassword = SecurityUtil.encryption(user.getPassword(), passwordCode);
        String idnumberCode = SecurityUtil.hmacSm3(user.getIdnumber(), SystemConstant.KEY);
        String enIdnumber = SecurityUtil.encryption(user.getIdnumber(), idnumberCode);
        User enUser = new User();
        enUser.setId(user.getId());
        enUser.setUsername(enUsername);
        enUser.setPassword(enPassword);
        enUser.setIdnumber(enIdnumber);
        enUser.setChannel(user.getChannel());
        Code code = new Code();
        code.setId(user.getId());
        code.setUsernameHash(usernameCode);
        code.setPasswordHash(passwordCode);
        code.setIdnumberHash(idnumberCode);
        userMapper.updateUserById(enUser);
        codeMapper.updateCodeById(code);
    }

    @Override
    public PageInfo<User> queryUserForConditionByPage(int pageNum, int pageSize, Map<String, Object> map) {
        PageHelper.startPage(pageNum, pageSize);
        List<User> enUsers = userMapper.selectUserForConditionByPage(map);
        PageInfo<User> pageInfo = new PageInfo<>(enUsers, 5);
        List<User> users = new ArrayList<>();
        for (User user : enUsers) {
            Code code = codeMapper.selectCodeById(user.getId());
            User deUser = new User();
            deUser.setId(user.getId());
            deUser.setUsername(SecurityUtil.decode(user.getUsername(), code.getUsernameHash()));
            deUser.setPassword(SecurityUtil.decode(user.getPassword(), code.getPasswordHash()));
            deUser.setPhone(SecurityUtil.decode(user.getPhone(), code.getPhoneHash()));
            deUser.setIdnumber(SecurityUtil.decode(user.getIdnumber(), code.getIdnumberHash()));
            deUser.setPermission(user.getPermission());
            deUser.setChannel(user.getChannel());
            users.add(deUser);
        }
        pageInfo.setList(users);
        return pageInfo;
    }

    @Override
    public List<User> queryUsersByIds(String[] id) {
        List<User> deUserList = new ArrayList<>();
        List<User> enUsers = userMapper.selectUsersByIds(id);
        for (User user : enUsers) {
            Code code = codeMapper.selectCodeById(user.getId());
            User deUser = SecurityUtil.decryption(user, code);
            deUserList.add(deUser);
        }
        return deUserList;
    }

    @Override
    public String encryptionByAES(List<User> users) {
        StringBuilder enUserStr = new StringBuilder();
        //随机生成AES密钥
        byte[] aesKey = SecureUtil.generateKey(SymmetricAlgorithm.AES.getValue()).getEncoded();
//        for (User user : users) {
        //使用AES算法加密
        String userAesStr = SecurityUtil.encryptionByAES(users, aesKey);
        //将所有加密的用户拼接
        enUserStr.append(userAesStr);
//        }
        //使用RSA算法加密AES的密钥
        String key = SecurityUtil.encryptionByRSA(aesKey);
        enUserStr.append(",");
        enUserStr.append(key);
        return enUserStr.toString();
    }

    @Override
    public List<User> decryptionByAES(String encryptionStr, String privateKey) {
        //拆分密文，用户密文和加密后的密钥
        String[] encryptionStrs = encryptionStr.split(",");
        String enStr = encryptionStrs[0];
        String enKey = encryptionStrs[1];
        //通过RSA算法解密AES的密钥
        byte[] key = SecurityUtil.decryptionByRSA(enKey, privateKey);
        //通过AES算法解密用户密文
        List<User> userList = SecurityUtil.decryptionByAES(enStr, key);
        return userList;
    }
}
