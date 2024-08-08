package com.xj.nobody.admin.service.impl;

import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.xj.nobody.admin.domain.SysRoleMenu;
import com.xj.nobody.admin.mapper.SysRoleMenuMapper;
import com.xj.nobody.admin.service.SysRoleMenuService;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

@Service
public class SysRoleMenuServiceImpl implements SysRoleMenuService {
    @Resource
    private SysRoleMenuMapper roleMenuMapper;

    @Override
    public int deleteRelation(Integer menuId) {
        return roleMenuMapper.delete(Wrappers.lambdaQuery(SysRoleMenu.class).eq(SysRoleMenu::getMenuId, menuId));
    }
}
