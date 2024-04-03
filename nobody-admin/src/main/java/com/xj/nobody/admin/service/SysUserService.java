package com.xj.nobody.admin.service;

import com.xj.nobody.commons.dto.UserDTO;

public interface SysUserService {
    UserDTO loadUserWithPerms(String username);
}
