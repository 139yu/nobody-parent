package com.xj.nobody.admin.controller;

import com.xj.nobody.admin.service.SysUserService;
import com.xj.nobody.commons.dto.UserDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("admin")
public class AdminController {
    @Autowired
    private SysUserService userService;
    @GetMapping("loadByUsername")
    public UserDTO loadByUsername(String username){
        return userService.loadUserWithPerms(username);
    }
}
