package com.security.user_security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * @Description:
 * @Author: Kang
 * @Version: 1.0
 */
@Controller
public class MainController {

    @GetMapping("main")
    public String toMain(){
        return "main";
    }
}
