package com.security.user_security;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.symmetric.AES;
import cn.hutool.crypto.symmetric.SymmetricAlgorithm;
import com.security.user_security.pojo.User;
import com.security.user_security.service.UserService;
import com.security.user_security.utils.SecurityUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import javax.annotation.Resource;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @Description: TODO
 * @Author: Kang
 * @CreateTime: 2023-03-31  15:49
 * @Version: 1.0
 */
@DisplayName("算法测试类")
@SpringBootTest
public class SecutityTest {

    @Resource
    UserService userService;

    @Test
    public void test01(){
        String name="111";
        String key="123456789";
        String code = SecurityUtil.hmacSm3(name, key);
        System.out.println("code："+code);
        String encryption = SecurityUtil.encryption(name, code);
        System.out.println("加密后的内容："+encryption);
        String decode = SecurityUtil.decode(encryption, code);
        System.out.println("解密后的内容："+decode);
    }

    @Test
    public void test02(){
        User user = new User();
        user.setUsername("张三");
        userService.encryption(user);
    }

    @Test
    public void decodeTest(){
        String str="0001111111111000000111";
        String code="d730d66557067a557c743a0583ddf55a5b819e00346f88ac321c772bac1359be";
        String password = SecurityUtil.decode(str, code);
        System.out.println(password);
    }

    @Test
    public void encryptStrTest(){
        String enPhone = SecurityUtil.encryptStr("15896885122");
        System.out.println(enPhone);
    }


    @Test
    public void testAesAndRsa(){
        String str="你怎么忘了,你先说的爱我";
        //随机生成密钥
        byte[] key = SecureUtil.generateKey(SymmetricAlgorithm.AES.getValue()).getEncoded();
        //获取RSA的公钥,私钥
        KeyPair pair = SecureUtil.generateKeyPair("RSA");
        PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();
        System.out.println("publicKey: "+Base64.encode(publicKey.getEncoded()));
        System.out.println("privateKey: "+Base64.encode(privateKey.getEncoded()));
        //构建
        AES enAes = SecureUtil.aes(key);
        //加密
        String encryptHex = enAes.encryptHex(str);
        //RSA算法公钥加密key
        RSA rsa1 = new RSA(null, publicKey);
        String enKey = Base64.encode(rsa1.encrypt(key, KeyType.PublicKey));
        System.out.println("加密后:"+encryptHex+"  加密后的key:"+ enKey);
        //RSA算法私钥解密key
        RSA rsa2 = new RSA(privateKey, null);
        byte[] deKey = rsa2.decrypt(Base64.decode(enKey), KeyType.PrivateKey);
        AES deAes = SecureUtil.aes(deKey);
        //解密
        String decryptStr = deAes.decryptStr(encryptHex, CharsetUtil.CHARSET_UTF_8);
        System.out.println("解密后:"+decryptStr+"  解密后的key:"+Base64.encode(deKey));
        System.out.println("加密前的key: "+Base64.encode(key));

    }

    @Test
    public void testAesAndRsa1(){
        String str="你怎么忘了,你先说的爱我";
        //随机生成密钥
        byte[] key = SecureUtil.generateKey(SymmetricAlgorithm.AES.getValue()).getEncoded();
        //获取RSA的公钥,私钥
        KeyPair pair = SecureUtil.generateKeyPair("RSA");
        PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();
        //通过base64，将公钥和私钥转为基于base64编码的便于存储的字符串
        String publicKeyStr = Base64.encode(publicKey.getEncoded());
        String privateKeyStr = Base64.encode(privateKey.getEncoded());
        System.out.println("publicKey: "+publicKeyStr);
        System.out.println("privateKey: "+privateKeyStr);
        //构建
        AES enAes = SecureUtil.aes(key);
        //加密
        String encryptHex = enAes.encryptHex(str);
        //RSA算法公钥加密key
        RSA rsa1 = new RSA(null, publicKeyStr);
        String enKey = Base64.encode(rsa1.encrypt(key, KeyType.PublicKey));
        System.out.println("加密后:"+encryptHex+"  加密后的key:"+ enKey);
        //RSA算法私钥解密key
        RSA rsa2 = new RSA(privateKeyStr, null);
        byte[] deKey = rsa2.decrypt(Base64.decode(enKey), KeyType.PrivateKey);
        AES deAes = SecureUtil.aes(deKey);
        //解密
        String decryptStr = deAes.decryptStr(encryptHex, CharsetUtil.CHARSET_UTF_8);
        System.out.println("解密后:"+decryptStr+"  解密后的key:"+Base64.encode(deKey));
        System.out.println("加密前的key: "+Base64.encode(key));
    }
}
