package com.xj.nobody.system.service.impl;

import com.xj.nobody.commons.entitys.SysUser;
import com.xj.nobody.system.mapper.SysUserMapper;
import com.xj.nobody.system.service.SysUserService;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

@Service
public class SysUserServiceImpl implements SysUserService {
    @Resource
    private SysUserMapper sysUserMapper;
    @Override
    public SysUser getById(Integer id) {
        return sysUserMapper.selectById(id);
    }
}
