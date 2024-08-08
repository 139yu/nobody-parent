package com.xj.nobody.admin.service;

import com.xj.nobody.admin.domain.SysUser;
import com.xj.nobody.admin.vo.FullUserInfoVo;
import com.xj.nobody.admin.vo.UserItemVo;
import com.xj.nobody.commons.dto.UserDTO;

import java.util.List;

public interface SysUserService {
    UserDTO loadUserWithPerms(String username);
    /**
     * 获取用户完整信息（包含菜单、资源）
     * @param userId
     * @return
     */
    FullUserInfoVo getFullUserInfo(int userId);

    List<UserItemVo> list(SysUser params);
}
