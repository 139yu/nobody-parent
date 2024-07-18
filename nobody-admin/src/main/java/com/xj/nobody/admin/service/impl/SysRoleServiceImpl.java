package com.xj.nobody.admin.service.impl;

import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.xj.nobody.admin.domain.SysResource;
import com.xj.nobody.admin.domain.SysRole;
import com.xj.nobody.admin.domain.SysRoleResource;
import com.xj.nobody.admin.mapper.SysResourceMapper;
import com.xj.nobody.admin.mapper.SysRoleMapper;
import com.xj.nobody.admin.mapper.SysRoleResourceMapper;
import com.xj.nobody.admin.service.SysRoleService;
import com.xj.nobody.commons.constants.RedisKey;
import com.xj.nobody.commons.service.RedisService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class SysRoleServiceImpl implements SysRoleService {
    @Resource
    private SysRoleMapper roleMapper;
    @Autowired
    private RedisService redisService;
    @Resource
    private SysResourceMapper resourceMapper;
    @Resource
    private SysRoleResourceMapper roleResourceMapper;
    @Value("${spring.application.name}")
    private String applicationName;
    @Override
    public List<SysRole> list(SysRole params) {
        return roleMapper.list(params);
    }

    @Override
    public List<SysRole> listByUserId(Integer userId) {
        return roleMapper.listByUserId(userId);
    }

    @Override
    public void loadRoleResourceCache() {
        Map<String,List<String>> roleResourceMap = new HashMap<>();
        List<SysRole> roleList = roleMapper.selectList(Wrappers.lambdaQuery(SysRole.class));
        List<SysResource> resourceList = resourceMapper.selectList(Wrappers.lambdaQuery(SysResource.class));
        List<SysRoleResource> roleResourceList = roleResourceMapper.selectList(Wrappers.lambdaQuery(SysRoleResource.class));
        for (SysResource resource : resourceList) {
            Set<Integer> roleIds = roleResourceList.stream().filter(roleResource -> roleResource.getResourceId().equals(resource.getId())).map(item -> item.getRoleId()).collect(Collectors.toSet());
            List<String> collect = roleList.stream().filter(role -> roleIds.contains(role.getId())).map(item -> item.getRoleKey()).collect(Collectors.toList());
            roleResourceMap.put("/" + applicationName + resource.getUrl(),collect);
        }
        redisService.del(RedisKey.ROLE_RESOURCE);
        redisService.hSetAll(RedisKey.ROLE_RESOURCE,roleResourceMap);
    }

}
