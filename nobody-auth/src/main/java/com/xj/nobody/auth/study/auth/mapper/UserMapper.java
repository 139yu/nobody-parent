package com.xj.nobody.auth.study.auth.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.xj.nobody.auth.study.auth.entity.User;
import org.apache.ibatis.annotations.Param;

public interface UserMapper extends BaseMapper<User> {
    int updatePassowrd(@Param("username") String username, @Param("newPassword") String newPassword);
}
