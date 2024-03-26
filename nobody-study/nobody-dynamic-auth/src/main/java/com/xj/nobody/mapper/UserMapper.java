package com.xj.nobody.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.xj.nobody.entity.Role;
import com.xj.nobody.entity.User;
import org.apache.ibatis.annotations.Param;

import java.util.List;

public interface UserMapper extends BaseMapper<User> {
    List<Role> getUserRoleByUid(@Param("uid") Integer uid);


    User loadUserByUsername(@Param("username") String username);
}
