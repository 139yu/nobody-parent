package com.xj.nobody.auth.study.define.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;


@Controller
@RequestMapping("test/define")
public class TestDefineController {

    @GetMapping("/index.html")
    public String index(){
        return "index";
    }

    @PostMapping("hello")
    @ResponseBody
    public String hello(){
        return "hello 111";
    }
}
