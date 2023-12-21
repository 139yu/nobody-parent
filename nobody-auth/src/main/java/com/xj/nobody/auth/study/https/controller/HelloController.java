package com.xj.nobody.auth.study.https.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("hello")
public class HelloController {

    @GetMapping("https")
    public String https(){
        return "https";
    }

    @GetMapping("http")
    public String http(){
        return "http";
    }
}
