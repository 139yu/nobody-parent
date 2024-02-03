package com.xj.nobody.auth.study.httpauth.controller;

import org.springframework.web.bind.annotation.GetMapping;

//@RestController
//@RequestMapping
public class FuckController {

    @GetMapping("fuck")
    public String fuck(){
        return "fuck";
    }
}
