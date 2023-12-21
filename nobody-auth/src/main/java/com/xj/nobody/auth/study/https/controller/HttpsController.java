package com.xj.nobody.auth.study.https.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("https")
@RestController
public class HttpsController {

    @GetMapping("hello")
    public String hello(){
        return "hello";
    }


    @GetMapping("index")
    public String index(){
        return "index";
    }
}
