package com.security.user_security.config;

import com.security.user_security.utils.LoginInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * @Description:
 * @Author: Kang
 * @Version: 1.0
 */
@Configuration
public class MvcConfig implements WebMvcConfigurer {
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new LoginInterceptor()).excludePathPatterns(
                "/css/**",
                "/fonts/**",
                "/images/**",
                "/jquery/**",
                "/js/**",
                "/user/login",
                "/user/register",
                "/user/toRegister",
                "/"
        ).order(1);
    }
}
