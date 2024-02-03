package com.xj.nobody.auth.study.https.controller;

import org.springframework.web.bind.annotation.GetMapping;

//@RequestMapping("https")
//@RestController
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
