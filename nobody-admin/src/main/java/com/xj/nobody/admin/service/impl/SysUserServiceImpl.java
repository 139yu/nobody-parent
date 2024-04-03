package com.xj.nobody.admin.service.impl;

import com.xj.nobody.admin.mapper.SysUserMapper;
import com.xj.nobody.admin.service.SysUserService;
import com.xj.nobody.commons.dto.UserDTO;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

@Service
public class SysUserServiceImpl implements SysUserService {
    @Resource
    private SysUserMapper userMapper;


    @Override
    public UserDTO loadUserWithPerms(String username) {
        return userMapper.loadUserWithPerms(username);
    }
}
