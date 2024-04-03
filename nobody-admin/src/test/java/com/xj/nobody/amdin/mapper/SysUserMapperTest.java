package com.xj.nobody.amdin.mapper;

import com.xj.nobody.admin.NobodyAdminApplication;
import com.xj.nobody.admin.mapper.SysUserMapper;
import com.xj.nobody.commons.dto.UserDTO;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import javax.annotation.Resource;

@SpringBootTest(classes = NobodyAdminApplication.class)
public class SysUserMapperTest {
    @Resource
    private SysUserMapper sysUserMapper;

    @Test
    public void selectUserByUsername() {
        UserDTO nobody = sysUserMapper.loadUserWithPerms("nobody");
        System.out.println(nobody);
    }
}
