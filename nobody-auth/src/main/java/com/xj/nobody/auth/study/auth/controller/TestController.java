package com.xj.nobody.auth.study.auth.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

//@RestController
//@RequestMapping("test")
public class TestController {

    @GetMapping("hello")
    public String hello(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String name = authentication.getName();
        Object credentials = authentication.getCredentials();
        return String.format("hello %s,you credentials is %s",name,credentials);
    }

}
