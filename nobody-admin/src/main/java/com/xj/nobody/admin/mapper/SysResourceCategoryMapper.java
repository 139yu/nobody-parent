package com.xj.nobody.admin.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.xj.nobody.admin.domain.SysResourceCategory;

import java.util.List;

public interface SysResourceCategoryMapper extends BaseMapper<SysResourceCategory> {
    List<SysResourceCategory> listWithItem();

    List<SysResourceCategory> list(SysResourceCategory params);

    int unique(SysResourceCategory resourceCategory);
}
