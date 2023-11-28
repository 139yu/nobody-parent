package com.xj.nobody.auth.controller;

import com.xj.nobody.auth.dto.LoginDTO;
import com.xj.nobody.commons.domain.R;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("auth/")
public class AuthController {

    @PostMapping("login")
    public R login(@RequestBody LoginDTO dto){
        return R.success();
    }
}
