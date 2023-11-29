package com.xj.nobody.system.controller;

import com.xj.nobody.commons.domain.R;
import com.xj.nobody.commons.entitys.SysUser;
import com.xj.nobody.system.service.SysUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/sys/user")
public class SysUserController {

    @Autowired
    private SysUserService sysUserService;

    @GetMapping("getOne")
    public R<SysUser> getById(@RequestParam("id") Integer id){
        return R.success(sysUserService.getById(id));
    }
}
