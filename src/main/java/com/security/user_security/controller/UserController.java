package com.security.user_security.controller;

import com.github.pagehelper.PageInfo;
import com.security.user_security.pojo.User;
import com.security.user_security.service.UserService;
import com.security.user_security.utils.*;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.system.ApplicationHome;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @Description:
 * @Author: Kang
 * @Version: 1.0
 */
@Controller
@CrossOrigin
public class UserController {

    @Autowired
    private UserService userService;


    @GetMapping("/user/toRegister")
    public String toRegister() {
        return "register";
    }

    @PostMapping("/user/register")
    @ResponseBody
    public Object register(User user, HttpSession session) {
        ReturnObject returnObject = new ReturnObject();
        //判断用户是否已经存在
        boolean isExist = userService.verification(user);
        if (isExist) {
            //用户已存在
            returnObject.setCode("0");
            return returnObject;
        }
        //用户不存在，用户加密，保存用户
        userService.encryption(user);
        session.setAttribute(SystemConstant.SESSION_USER, user);
        returnObject.setCode("1");
        return returnObject;
    }

    @PostMapping("/user/login")
    @ResponseBody
    public Object login(@RequestParam String phone,
                        @RequestParam String password,
                        HttpSession session) {
        ReturnObject returnObject = new ReturnObject();
        UserDTO userDTO = userService.queryUserAndCodeByPhoneWithPassword(phone, password);
        User deUser = userService.decryption(userDTO.getUser(), userDTO.getCode());
        if (deUser != null) {
            session.setAttribute(SystemConstant.SESSION_USER, deUser);
            returnObject.setCode("0");
        }
        return returnObject;
    }

    @GetMapping("/user/logout")
    public String logout(HttpSession session) throws IOException {
        session.removeAttribute(SystemConstant.SESSION_USER);
        return "redirect:/";
    }

    @GetMapping("/user/toDetail")
    public String toDetail() {
        return "details/index";
    }

    @GetMapping("/user/toUserList")
    public String toUserList() {
        return "user/index";
    }

    @PostMapping("/user/editUser")
    @ResponseBody
    public Object editUser(User user, HttpSession session) {
        ReturnObject returnObject = new ReturnObject();
        userService.editUserById(user);
        session.setAttribute(SystemConstant.SESSION_USER, user);
        return returnObject;
    }

    @PostMapping("/user/queryUserForConditionByPage")
    @ResponseBody
    public Object queryUserForConditionByPage(@RequestParam int pageNum,
                                              @RequestParam int pageSize,
                                              @RequestParam String username,
                                              @RequestParam String phone,
                                              @RequestParam String channel) {
        Map<String, Object> map = new HashMap<>();
        ReturnObject returnObject = new ReturnObject();
        String enUsername = "";
        String enPhone = "";
        if (username != null && username != "") {
            enUsername = SecurityUtil.encryptStr(username);
        }
        if (phone != null && phone != "") {
            enPhone = SecurityUtil.encryptStr(phone);
        }
        map.put("username", enUsername);
        map.put("phone", enPhone);
        map.put("channel", channel);
        PageInfo<User> pageInfo = userService.queryUserForConditionByPage(pageNum, pageSize, map);
        returnObject.setRetData(pageInfo);
        return returnObject;
    }

    @GetMapping("/user/exportUserOpt")
    public ResponseEntity<InputStreamResource> exportUserOpt(String[] id) throws IOException {
        //得到解密后的用户信息
        List<User> users = userService.queryUsersByIds(id);
        for (User user : users) {
            System.out.println(user);
        }
        //通过AES加密用户+RSA加密AES密钥
        String enUsersStr = userService.encryptionByAES(users);
        File file = new File("src/main/resources/files/userList.txt");
        FileWriter fw = null;
        try {
            fw = new FileWriter(file);
            fw.write(enUsersStr);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
        }
        if (fw != null) {
            try {
                fw.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        FileSystemResource fileSystemResource = new FileSystemResource(file);
        HttpHeaders headers = new HttpHeaders();
        headers.add("Cache-Control", "no-cache, no-store, must-revalidate");
        headers.add("Content-Disposition", String.format("attachment; filename=\"%s\"", fileSystemResource.getFilename()));
        headers.add("Pragma", "no-cache");
        headers.add("Expires", "0");
        return ResponseEntity
                .ok()
                .headers(headers)
                .contentLength(fileSystemResource.contentLength())
                .contentType(MediaType.parseMediaType("application/octet-stream"))
                .body(new InputStreamResource(fileSystemResource.getInputStream()));
    }

    @PostMapping("/user/importUsers")
    @ResponseBody
    public Object importUsers(@RequestParam("userFile") MultipartFile userFile,
                              @RequestParam("privateKeyFile") MultipartFile privateKeyFile,
                              HttpServletRequest req) throws IOException {
        ReturnObject returnObject = new ReturnObject();
        if (!userFile.isEmpty()) {
            ApplicationHome applicationHome = new ApplicationHome(this.getClass());
            String realPath = applicationHome.getDir().getParentFile().getParentFile().getAbsolutePath() + "/src/main/resources/files/";
            String userFilename = userFile.getOriginalFilename();
            //读取用户文件中的用户加密信息
            File file = new File(realPath + userFilename);
            userFile.transferTo(file);
            cn.hutool.core.io.file.FileReader fr = new cn.hutool.core.io.file.FileReader(file);
            String userStr = fr.readString();
            System.out.println(userStr);
            //读取密钥文件中的私钥
            String privateKeyFileName = privateKeyFile.getOriginalFilename();
            File keyFile = new File(realPath + privateKeyFileName);
            privateKeyFile.transferTo(keyFile);
            cn.hutool.core.io.file.FileReader keyFr = new cn.hutool.core.io.file.FileReader(keyFile);
            String privateKeyStr = keyFr.readString();
            //通过AES算法解密
            List<User> userList = userService.decryptionByAES(userStr, privateKeyStr);
            if (userList.size()==0){
                returnObject.setCode("0");
                returnObject.setMessage("导入用户信息失败，请确认用户加密文件和私钥后重新导入！");
                return returnObject;
            }
            for (User user : userList) {
                //将用户加密并存储到数据库中
                userService.encryption(user);
                System.err.println(user);
            }
            returnObject.setCode("1");
            returnObject.setRetData(userList.size());
            return returnObject;
        }
        returnObject.setCode("0");
        returnObject.setMessage("导入用户信息失败，请确认用户加密文件和私钥后重新导入！");
        return returnObject;
    }
}
