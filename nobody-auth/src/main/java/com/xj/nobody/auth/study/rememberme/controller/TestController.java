package com.xj.nobody.auth.study.rememberme.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("hello")
    public String hello(){
        return "hello";
    }
    @GetMapping("admin")
    public String admin(){
        return "admin";
    }
    @GetMapping("rememberMe")
    public String rememberMe(){
        return "rememberMe";
    }
}
