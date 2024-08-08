package com.xj.nobody.admin.service.impl;

import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.xj.nobody.admin.domain.SysResource;
import com.xj.nobody.admin.domain.SysResourceCategory;
import com.xj.nobody.admin.mapper.SysResourceCategoryMapper;
import com.xj.nobody.admin.mapper.SysResourceMapper;
import com.xj.nobody.admin.service.SysResourceCategoryService;
import com.xj.nobody.commons.exception.BusinessException;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.Collections;
import java.util.List;

@Service
public class SysResourceCategoryServiceImpl implements SysResourceCategoryService {
    @Resource
    private SysResourceCategoryMapper resourceCategoryMapper;
    @Resource
    private SysResourceMapper resourceMapper;
    @Override
    public List<SysResourceCategory> listWithItem() {
        return resourceCategoryMapper.listWithItem();
    }

    @Override
    public List<SysResourceCategory> list(SysResourceCategory params) {
        return resourceCategoryMapper.list(params);
    }

    @Override
    public int addCategory(SysResourceCategory resourceCategory) throws BusinessException {
        boolean exists = resourceCategoryMapper.exists(Wrappers.lambdaQuery(SysResourceCategory.class).eq(SysResourceCategory::getName, resourceCategory.getName()));
        if (exists) {
            throw new BusinessException("名称不能重复");
        }
        return resourceCategoryMapper.insert(resourceCategory);
    }

    @Override
    public int updateCategory(SysResourceCategory resourceCategory) throws BusinessException {
        if (!unique(resourceCategory)) {
            throw new BusinessException("分类名称不能重复");
        }

        return resourceCategoryMapper.updateById(resourceCategory);
    }

    @Override
    public boolean unique(SysResourceCategory resourceCategory) {
        return !(resourceCategoryMapper.unique(resourceCategory) > 0);
    }

    @Override
    public int deleteCategory(Integer id) throws BusinessException {
        boolean exists = resourceMapper.exists(Wrappers.lambdaQuery(SysResource.class).eq(SysResource::getCategoryId, id));
        if (exists) {
            throw new BusinessException("该分类下存在资源，不能删除");
        }

        return resourceCategoryMapper.deleteById(id);
    }
}
