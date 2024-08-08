package com.xj.nobody.admin.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.xj.nobody.admin.domain.SysMenu;
import org.apache.ibatis.annotations.Param;

import java.util.List;

public interface SysMenuMapper extends BaseMapper<SysMenu> {
    List<SysMenu> getUserMenu(@Param("userId") int userId);

    int selectExists(SysMenu menu);

    int unique(SysMenu menu);
}
