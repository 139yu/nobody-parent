package com.xj.nobody.admin.service;

import com.xj.nobody.admin.domain.SysResourceCategory;
import com.xj.nobody.commons.exception.BusinessException;

import java.util.List;

public interface SysResourceCategoryService {
    List<SysResourceCategory> listWithItem();

    List<SysResourceCategory> list(SysResourceCategory params);

    int addCategory(SysResourceCategory resourceCategory) throws BusinessException;

    int updateCategory(SysResourceCategory resourceCategory) throws BusinessException;

    boolean unique(SysResourceCategory resourceCategory);

    int deleteCategory(Integer id) throws BusinessException;
}
