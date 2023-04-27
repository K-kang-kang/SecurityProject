package com.security.user_security.utils;

import com.security.user_security.pojo.User;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * @Description:
 * @Author: Kang
 * @Version: 1.0
 */
public class LoginInterceptor implements HandlerInterceptor {
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        HttpSession session = request.getSession();
        User user = (User) session.getAttribute(SystemConstant.SESSION_USER);
        if (user==null){
            response.sendRedirect(request.getContextPath()+"/");
            return false;
        }
        return true;
    }
}
