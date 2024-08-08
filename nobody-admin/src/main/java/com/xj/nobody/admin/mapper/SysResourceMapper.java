package com.xj.nobody.admin.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.xj.nobody.admin.domain.SysMenu;
import com.xj.nobody.admin.domain.SysResource;
import org.apache.ibatis.annotations.Param;

import java.util.List;

public interface SysResourceMapper extends BaseMapper<SysResource> {
    List<SysResource> getUserResources(@Param("userId") Integer userId);

    int selectExists(SysResource resource);

    int unique(SysResource resource);
}
