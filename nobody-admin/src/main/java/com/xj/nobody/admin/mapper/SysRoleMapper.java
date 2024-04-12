package com.xj.nobody.admin.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.xj.nobody.admin.domain.SysRole;

import java.util.List;

public interface SysRoleMapper extends BaseMapper<SysRole> {

    List<SysRole> list(SysRole params);

    List<SysRole> listByUserId(Integer userId);
}
