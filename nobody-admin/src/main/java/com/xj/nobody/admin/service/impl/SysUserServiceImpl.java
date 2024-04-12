package com.xj.nobody.admin.service.impl;

import com.xj.nobody.admin.domain.SysRole;
import com.xj.nobody.admin.mapper.SysUserMapper;
import com.xj.nobody.admin.service.SysRoleService;
import com.xj.nobody.admin.service.SysUserService;
import com.xj.nobody.commons.dto.UserDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.List;

@Service
public class SysUserServiceImpl implements SysUserService {
    @Resource
    private SysUserMapper userMapper;
    @Autowired
    private SysRoleService roleService;

    @Override
    public UserDTO loadUserWithPerms(String username) {
        UserDTO userDTO = userMapper.loadUserByUsername(username);
        if (userDTO == null) {
            return null;
        }
        List<SysRole> roles = roleService.listByUserId(userDTO.getId());
        List<String> roleKeys = new ArrayList<>();
        for (SysRole role : roles) {
            roleKeys.add(role.getRoleKey());
        }
        userDTO.setRoleList(roleKeys);
        return userDTO;
    }
}
