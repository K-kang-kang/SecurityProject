package com.security.user_security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @Description:
 * @Author: Kang
 * @Version: 1.0
 */
@Controller
public class IndexController {


    @RequestMapping("/")
    public String loginPage(){
        return "login";
    }
}
