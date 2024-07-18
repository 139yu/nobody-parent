package com.xj.nobody.admin.controller;

import com.xj.nobody.admin.dto.UserLoginParam;
import com.xj.nobody.admin.service.AdminService;
import com.xj.nobody.admin.service.SysUserService;
import com.xj.nobody.commons.api.CommonResult;
import com.xj.nobody.commons.dto.UserDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("admin")
public class AdminController {
    @Autowired
    private SysUserService userService;
    @Autowired
    private AdminService adminService;
    @GetMapping("loadByUsername")
    public UserDTO loadByUsername(@RequestParam String username){
        return userService.loadUserWithPerms(username);
    }
    @PostMapping("login")
    public CommonResult login(@RequestBody @Validated UserLoginParam loginParam){
        return adminService.login(loginParam.getUsername(),loginParam.getPassword());
    }
    
    @GetMapping("test")
    public String test(){
        return "test";
    }
}
