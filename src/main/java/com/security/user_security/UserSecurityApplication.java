package com.security.user_security;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@MapperScan("com.security.user_security.mapper")
@SpringBootApplication
public class UserSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(UserSecurityApplication.class, args);
    }

}
