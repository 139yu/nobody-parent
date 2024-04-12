package com.xj.nobody.admin.service;


import com.xj.nobody.admin.domain.SysRole;

import java.util.List;

public interface SysRoleService {

    List<SysRole> list(SysRole params);

    List<SysRole> listByUserId(Integer userId);

    void loadRoleResourceCache();
}
