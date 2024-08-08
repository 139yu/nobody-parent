package com.xj.nobody.admin.service.impl;

import com.xj.nobody.admin.domain.SysMenu;
import com.xj.nobody.admin.domain.SysResource;
import com.xj.nobody.admin.domain.SysRole;
import com.xj.nobody.admin.domain.SysUser;
import com.xj.nobody.admin.mapper.SysMenuMapper;
import com.xj.nobody.admin.mapper.SysResourceMapper;
import com.xj.nobody.admin.mapper.SysUserMapper;
import com.xj.nobody.admin.service.SysMenuService;
import com.xj.nobody.admin.service.SysResourceService;
import com.xj.nobody.admin.service.SysRoleService;
import com.xj.nobody.admin.service.SysUserService;
import com.xj.nobody.admin.vo.FullUserInfoVo;
import com.xj.nobody.admin.vo.UserItemVo;
import com.xj.nobody.commons.dto.UserDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class SysUserServiceImpl implements SysUserService {
    @Resource
    private SysUserMapper userMapper;
    @Autowired
    private SysRoleService roleService;
    @Autowired
    private SysMenuService menuService;
    @Autowired
    private SysResourceService resourceService;
    @Override
    public UserDTO loadUserWithPerms(String username) {
        UserDTO userDTO = userMapper.loadUserByUsername(username);
        if (userDTO == null) {
            return null;
        }

        List<SysRole> roles = roleService.listByUserId(userDTO.getUserId());
        List<String> roleKeys = new ArrayList<>();
        for (SysRole role : roles) {
            roleKeys.add(role.getRoleKey());
        }
        userDTO.setRoleList(roleKeys);
        return userDTO;
    }

    @Override
    public FullUserInfoVo getFullUserInfo(int userId) {
        SysUser user = userMapper.selectById(userId);
        FullUserInfoVo fullUserInfo = new FullUserInfoVo();
        fullUserInfo.setId(user.getId());
        fullUserInfo.setUsername(user.getUsername());
        fullUserInfo.setAvatar(user.getAvatar());
        fullUserInfo.setMenuList(menuService.getUserMenus(userId));
        List<SysResource> userResources = resourceService.getUserResources(userId);
        List<String> resourcePath = userResources.stream().map(SysResource::getUrl).collect(Collectors.toList());
        fullUserInfo.setResourceList(resourcePath);
        return fullUserInfo;
    }

    @Override
    public List<UserItemVo> list(SysUser params) {
        return userMapper.list(params);
    }
}
