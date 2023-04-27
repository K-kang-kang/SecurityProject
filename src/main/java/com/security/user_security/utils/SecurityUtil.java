package com.security.user_security.utils;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.HexUtil;
import cn.hutool.core.util.IdUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.symmetric.AES;
import cn.hutool.crypto.symmetric.SymmetricAlgorithm;
import com.security.user_security.pojo.Code;
import com.security.user_security.pojo.User;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * @Description: 工具类
 * @Author: Kang
 * @Version: 1.0
 */
public class SecurityUtil {


    /**
     * description: 根据密钥与str通过HMAC-SM3计算得到code十六进制消息认证码
     *
     * @author: Kang
     * @param str: str:要加密的内容
     * @param key: code: 公司的密钥
     * @return: java.lang.String
     */
    public static String hmacSm3(String str, String key) {
        return CryptoSM3.bytesToHexString(CryptoSM3.createHmac(str.getBytes(), key.getBytes()));
    }


    /**
     * description: 通过code消息认证码异或Str，返回异或加密后的二进制字符串
     *
     * @author: Kang
     * @param str:要加密的内容
     * @param code: 公司的密钥
     * @return: java.lang.String
     */
    public static String encryption(String str, String code) {
        //将字符串转为16进制字符串
        String hexStr = HexUtil.encodeHexStr(str);
        //将两个16进制字符串转换为二进制字符串
        String binaryStr = new BigInteger(hexStr, 16).toString(2);
        String binaryCode = new BigInteger(code, 16).toString(2);
        //将两个二进制字符串进行异或
        byte[] strBytes = binaryStr.getBytes(StandardCharsets.UTF_8);
        byte[] codeBytes = binaryCode.getBytes(StandardCharsets.UTF_8);
        StringBuilder resultStr = new StringBuilder();
        for (int i = 0; i < strBytes.length; i++) {
            resultStr.append(strBytes[i] ^ codeBytes[i]);
        }
        return resultStr.toString();
    }


    /**
     * description: 解密用户加密信息表中加密的内容
     *
     * @author: Kang
     * @param code: 数据库消息认证码表中的消息认证码
     * @param str:  数据库用户加密信息表中存储的内容
     * @return: java.lang.String
     */
    public static String decode(String str, String code) {
        byte[] strBytes = str.getBytes(StandardCharsets.UTF_8);
        String binaryCode = new BigInteger(code, 16).toString(2);
        byte[] binaryCodeBytes = binaryCode.getBytes(StandardCharsets.UTF_8);
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < strBytes.length; i++) {
            result.append(strBytes[i] ^ binaryCodeBytes[i]);
        }
        return HexUtil.decodeHexStr(new BigInteger(result.toString(), 2).toString(16));

    }


    /**
     * description: 将str通过HMAC-SM3异或加密，返回加密后的str
     *
     * @author: Kang
     * @param str: 要加密的字符串
     * @return: java.lang.String
     */
    public static String encryptStr(String str) {
        String strCode = SecurityUtil.hmacSm3(str, SystemConstant.KEY);
        String enStr = SecurityUtil.encryption(str, strCode);
        return enStr;
    }

    /**
     * description: 加密User,返回用户加密对象和用户消息码对象；
     * 如果用户id为空，则生成id；
     * 如果用户id不为空，则使用原有用户id
     * @author: Kang
     * @param user: 要加密的用户信息
     * @return: void
     */
    public static UserDTO encryption(User user) {
        String id = IdUtil.simpleUUID();
        if (user.getId() != null && user.getId() != "") {
            id=user.getId();
        }
        String usernameCode = SecurityUtil.hmacSm3(user.getUsername(), SystemConstant.KEY);
        String enUsername = SecurityUtil.encryption(user.getUsername(), usernameCode);
        String passwordCode = SecurityUtil.hmacSm3(user.getPassword(), SystemConstant.KEY);
        String enPassword = SecurityUtil.encryption(user.getPassword(), passwordCode);
        String idnumberCode = SecurityUtil.hmacSm3(user.getIdnumber(), SystemConstant.KEY);
        String enIdnumber = SecurityUtil.encryption(user.getIdnumber(), idnumberCode);
        String phoneCode = SecurityUtil.hmacSm3(user.getPhone(), SystemConstant.KEY);
        String enPhone = SecurityUtil.encryption(user.getPhone(), phoneCode);
        User enUser = new User();
        enUser.setUsername(enUsername);
        enUser.setPassword(enPassword);
        enUser.setIdnumber(enIdnumber);
        enUser.setPhone(enPhone);
        enUser.setChannel(user.getChannel());
        enUser.setId(id);
        Code code = new Code();
        code.setUsernameHash(usernameCode);
        code.setPasswordHash(passwordCode);
        code.setIdnumberHash(idnumberCode);
        code.setPhoneHash(phoneCode);
        code.setId(id);
        System.out.println(enUser);
        System.out.println(code);
        UserDTO userDTO = new UserDTO();
        userDTO.setUser(enUser);
        userDTO.setCode(code);
        return userDTO;
    }

    /**
     * description: 解密用户
     *
     * @author: Kang
     * @param enUser: 加密后的用户信息
     * @param code:  用户消息认证码
     * @return: 解密后的用户
     */
    public static User decryption(User enUser, Code code) {
        if (enUser == null || code == null) {
            return null;
        }
        User deUser = new User();
        String username = SecurityUtil.decode(enUser.getUsername(), code.getUsernameHash());
        String password = SecurityUtil.decode(enUser.getPassword(), code.getPasswordHash());
        String idnumber = SecurityUtil.decode(enUser.getIdnumber(), code.getIdnumberHash());
        String phone = SecurityUtil.decode(enUser.getPhone(), code.getPhoneHash());
        deUser.setId(enUser.getId());
        deUser.setUsername(username);
        deUser.setPassword(password);
        deUser.setIdnumber(idnumber);
        deUser.setPhone(phone);
        deUser.setPermission(enUser.getPermission());
        deUser.setChannel(enUser.getChannel());
        return deUser;
    }

    /**
     * description: 将用户集合转化为用户字符串，用户间用";"隔开，属性间用","隔开，使用AES算法加密用户字符串，返回加密后的字符串
     *
     * @author: Kang
     * @param users: 要使用AES加密的用户明文对象集合
     * @param aesKey: AES密钥
     * @return: java.lang.String
     */
    public static String encryptionByAES(List<User> users, byte[] aesKey) {
        StringBuilder userStr = new StringBuilder();
        //构建AES
        AES aes = SecureUtil.aes(aesKey);
        for (User user : users) {
            //加密
            String id = user.getId() + ",";
            String username = user.getUsername() + ",";
            String password = user.getPassword() + ",";
            String permission = user.getPermission() + ",";
            String idnumber = user.getIdnumber() + ",";
            String phone = user.getPhone() + ",";
            String channel = user.getChannel() + ";";
            userStr.append(id);
            userStr.append(username);
            userStr.append(password);
            userStr.append(permission);
            userStr.append(idnumber);
            userStr.append(phone);
            userStr.append(channel);
        }
        System.out.println(userStr.toString());
        String enUserStr = aes.encryptHex(userStr.toString());
        return enUserStr;
    }

    /**
     * description: 使用AES算法解密用户密文，返回解密后的用户集合
     *
     * @param enUserStr : 用户密文
     * @param key       :AES的密钥
     * @author: Kang
     * @date: 2023/4/6 21:05
     * @return: java.util.List<com.security.user_security.pojo.User>
     */
    public static List<User> decryptionByAES(String enUserStr, byte[] key) {
        List<User> userList = new ArrayList<>();
        AES aes = SecureUtil.aes(key);
        String decryptStr = aes.decryptStr(enUserStr);
        String[] userStrs = decryptStr.split(";");
        for (String userStr : userStrs) {
            User user = new User();
            String[] propertys = userStr.split(",");
            for (int i = 0; i < propertys.length; i++) {
                switch (i) {
                    case 0:
                        user.setId(propertys[0]);
                        break;
                    case 1:
                        user.setUsername(propertys[1]);
                        break;
                    case 2:
                        user.setPassword(propertys[2]);
                        break;
                    case 3:
                        user.setPermission(propertys[3]);
                        break;
                    case 4:
                        user.setIdnumber(propertys[4]);
                        break;
                    case 5:
                        user.setPhone(propertys[5]);
                        break;
                    case 6:
                        user.setChannel(propertys[6]);
                        break;
                }
            }
            userList.add(user);
        }
        return userList;
    }


    /**
     * description: 使用RSA算法加密AES的密钥
     *
     * @author: Kang
     * @param aesKey: AES的密钥
     * @return: java.lang.String
     */
    public static String encryptionByRSA(byte[] aesKey) {
        RSA rsa = new RSA(null, SystemConstant.PUBLICKEY);
        return Base64.encode(rsa.encrypt(aesKey, KeyType.PublicKey));
    }

    /**
     * description: 使用RSA算法解密AES的密钥
     *
     * @author: Kang
     * @Param enKey: 加密后的AES的密钥
     * @param privateKey: 私钥
     * @return: byte[]
     */
    public static byte[] decryptionByRSA(String enKey, String privateKey) {
        RSA rsa = new RSA(privateKey, null);
        return rsa.decrypt(Base64.decode(enKey), KeyType.PrivateKey);
    }


}
