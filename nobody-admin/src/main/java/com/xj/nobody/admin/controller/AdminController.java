package com.xj.nobody.admin.controller;

import com.xj.nobody.admin.dto.UserLoginParam;
import com.xj.nobody.admin.service.AdminService;
import com.xj.nobody.admin.service.SysUserService;
import com.xj.nobody.admin.utils.SecurityUtils;
import com.xj.nobody.commons.api.CommonResult;
import com.xj.nobody.commons.api.ResultCode;
import com.xj.nobody.commons.dto.UserDTO;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.text.ParseException;

@RestController
@RequestMapping("admin")
@Slf4j
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

    @GetMapping("getFullUserInfo")
    public CommonResult getFullUserInfo() throws ParseException {
        UserDTO currentUser = SecurityUtils.getCurrentUser();
        if (currentUser == null) {
            return CommonResult.failed(ResultCode.UNAUTHORIZED);
        }
        return CommonResult.success(userService.getFullUserInfo(currentUser.getUserId()));
    }
}
