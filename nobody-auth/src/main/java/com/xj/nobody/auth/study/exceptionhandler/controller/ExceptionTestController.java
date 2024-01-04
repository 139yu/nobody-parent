package com.xj.nobody.auth.study.exceptionhandler.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("exception")
public class ExceptionTestController {

    @GetMapping("test")
    public String test(){
        return "test";
    }
    @GetMapping("admin")
    public String admin(){
        return "admin";
    }
}
