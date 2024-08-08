package com.xj.nobody.admin.service;

import com.xj.nobody.admin.domain.SysResource;
import com.xj.nobody.admin.domain.SysResourceCategory;
import com.xj.nobody.commons.exception.BusinessException;

import java.util.List;

public interface SysResourceService {

    List<SysResource> getUserResources(Integer userId);

    int addResource(SysResource resource) throws BusinessException;

    boolean exists(SysResource resource);

    int updateResource(SysResource resource) throws BusinessException;

    boolean unique(SysResource resource);

    int deleteResource(Integer id);
}
