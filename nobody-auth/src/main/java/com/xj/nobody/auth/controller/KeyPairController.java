package com.xj.nobody.auth.controller;

import com.xj.nobody.auth.config.AccessTokenConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("rsa")
public class KeyPairController {
    @Autowired
    private AccessTokenConfig tokenConfig;

    /**
     * 获取RSA公钥接口
     * @return
     */
    @GetMapping("publicKey")
    public String key(){
        return tokenConfig.jwkSet().toString();
    }
}
