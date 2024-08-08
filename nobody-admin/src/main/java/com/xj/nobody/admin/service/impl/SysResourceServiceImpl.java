package com.xj.nobody.admin.service.impl;

import com.xj.nobody.admin.domain.SysResource;
import com.xj.nobody.admin.domain.SysResourceCategory;
import com.xj.nobody.admin.mapper.SysResourceCategoryMapper;
import com.xj.nobody.admin.mapper.SysResourceMapper;
import com.xj.nobody.admin.service.SysResourceService;
import com.xj.nobody.commons.exception.BusinessException;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.Collections;
import java.util.List;

@Service
public class SysResourceServiceImpl implements SysResourceService {
    @Resource
    private SysResourceMapper resourceMapper;
    @Override
    public List<SysResource> getUserResources(Integer userId) {
        return resourceMapper.getUserResources(userId);
    }

    @Override
    public int addResource(SysResource resource) throws BusinessException {
        if (exists(resource)) {
            throw new BusinessException("资源已存在");
        }
        return resourceMapper.insert(resource);
    }

    @Override
    public boolean exists(SysResource resource) {
        return resourceMapper.selectExists(resource) > 0;
    }

    @Override
    public int updateResource(SysResource resource) throws BusinessException {
        if (unique(resource)) {
            throw new BusinessException("资源已存在");
        }
        return resourceMapper.updateById(resource);
    }

    @Override
    public boolean unique(SysResource resource) {
        return !(resourceMapper.unique(resource) > 0);
    }

    @Override
    public int deleteResource(Integer id) {
        return resourceMapper.deleteById(id);
    }


}
