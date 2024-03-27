package com.xj.nobody.oauth2.controller;

import com.xj.nobody.oauth2.entity.CustomerOAuth2User;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("test")
public class TestController {
    @GetMapping("hello")
    public CustomerOAuth2User hello(){
        return (CustomerOAuth2User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }
}
