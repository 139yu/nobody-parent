package com.xj.nobody.admin.service;

import com.xj.nobody.admin.domain.SysUser;
import com.xj.nobody.commons.dto.UserDTO;

public interface SysUserService {
    UserDTO loadUserByUsername(String username);

    SysUser selectUserByUsername(String username);
}
