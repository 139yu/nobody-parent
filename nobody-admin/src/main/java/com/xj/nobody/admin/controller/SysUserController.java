package com.xj.nobody.admin.controller;

import com.xj.nobody.admin.domain.SysUser;
import com.xj.nobody.admin.service.SysUserService;
import com.xj.nobody.admin.vo.UserItemVo;
import com.xj.nobody.commons.api.CommonResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("user")
public class SysUserController {
    @Autowired
    private SysUserService userService;

    @GetMapping("list")
    public CommonResult<List<UserItemVo>> list(@RequestParam SysUser params){
        return CommonResult.success(userService.list(params));
    }
}
