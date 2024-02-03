package com.xj.nobody.auth.study.authority.component;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;

@Component
public class PermissionExpression {
    public boolean checkId(Authentication authentication,Integer userId){
        return userId % 2 == 0;
    }

    public boolean check(HttpServletRequest req){
        return "nobody".equals(req.getParameter("username"));
    }
}
