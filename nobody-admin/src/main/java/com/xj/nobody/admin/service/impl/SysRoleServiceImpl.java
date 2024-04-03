package com.xj.nobody.admin.service.impl;

import cn.hutool.core.util.StrUtil;
import com.xj.nobody.admin.domain.SysMenu;
import com.xj.nobody.admin.domain.SysRole;
import com.xj.nobody.admin.mapper.SysRoleMapper;
import com.xj.nobody.admin.service.SysRoleService;
import com.xj.nobody.commons.service.RedisService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class SysRoleServiceImpl implements SysRoleService {
    @Resource
    private SysRoleMapper roleMapper;
    @Autowired
    private RedisService redisService;

    @Override
    public List<SysRole> listWithMenu(SysRole params) {
        return roleMapper.listWithMenu(params);
    }

    @Override
    public void loadRoleMenuCache() {
        List<SysRole> listAll = listWithMenu(new SysRole());
        Map<String,List<String>> roleMenuPathMap = new HashMap<>();
        for (SysRole item : listAll) {
            String roleKey = item.getRoleKey();
            List<String> paths = new ArrayList<>();
            for (SysMenu sysMenu : item.getMenuList()) {
                if (StrUtil.isNotEmpty(sysMenu.getPath())) {
                    paths.add(sysMenu.getPath());
                }
            }
            roleMenuPathMap.put(roleKey,paths);
        }
    }

}
