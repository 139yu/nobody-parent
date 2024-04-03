package com.xj.nobody.admin.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.xj.nobody.commons.dto.UserDTO;

public interface SysUserMapper extends BaseMapper<SysUserMapper> {
    UserDTO loadUserWithPerms(String username);
}
