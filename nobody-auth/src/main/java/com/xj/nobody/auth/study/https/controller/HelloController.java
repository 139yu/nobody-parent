package com.xj.nobody.auth.study.https.controller;

import org.springframework.web.bind.annotation.GetMapping;

//@RestController
//@RequestMapping("hello")
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
