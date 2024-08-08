package com.xj.nobody.admin.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.xj.nobody.admin.domain.SysUser;
import com.xj.nobody.admin.vo.UserItemVo;
import com.xj.nobody.commons.dto.UserDTO;

import java.util.List;

public interface SysUserMapper extends BaseMapper<SysUser> {
    UserDTO loadUserByUsername(String username);

    List<UserItemVo> list(SysUser params);
}
