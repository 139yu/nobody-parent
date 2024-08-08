package com.xj.nobody.admin.controller;

import com.xj.nobody.admin.domain.SysMenu;
import com.xj.nobody.admin.service.SysMenuService;
import com.xj.nobody.commons.api.CommonResult;
import com.xj.nobody.commons.exception.BusinessException;
import com.xj.nobody.commons.validate.ValidateGroup;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("menu")
public class SysMenuController {

    @Autowired
    private SysMenuService menuService;

    @GetMapping("listTree")
    public CommonResult listTree(){
        return CommonResult.success(menuService.listTree());
    }

    @PostMapping("addMenu")
    public CommonResult addMenu(@RequestBody @Validated(value = {ValidateGroup.AddGroup.class}) SysMenu menu) throws BusinessException {
        menuService.addMenu(menu);
        return CommonResult.success();
    }

    @PostMapping("updateMenu")
    public CommonResult updateMenu(@RequestBody @Validated(value = {ValidateGroup.UpdateGroup.class}) SysMenu menu) throws BusinessException {
        menuService.updateMenu(menu);
        return CommonResult.success();
    }

    @PostMapping("delete/{id}")
    public CommonResult delete(@PathVariable Integer id) throws BusinessException {
        menuService.delete(id);
        return CommonResult.success();
    }

    @PostMapping("changeHidden/{id}/{hidden}")
    public CommonResult changeHidden(@PathVariable Integer id,@PathVariable Integer hidden) throws BusinessException {
        SysMenu menu = new SysMenu();
        menu.setId(id);
        menu.setHidden(hidden);
        menuService.updateMenu(menu);
        return CommonResult.success();
    }
}
