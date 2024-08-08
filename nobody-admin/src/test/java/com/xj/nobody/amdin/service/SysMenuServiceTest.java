package com.xj.nobody.amdin.service;

import cn.hutool.json.JSONUtil;
import com.xj.nobody.admin.NobodyAdminApplication;
import com.xj.nobody.admin.domain.SysMenu;
import com.xj.nobody.admin.service.SysMenuService;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

@Slf4j
@SpringBootTest(classes = NobodyAdminApplication.class)
public class SysMenuServiceTest {

    @Autowired
    private SysMenuService menuService;

    @Test
    public void userMenus() {
        List<SysMenu> userMenus = menuService.getUserMenus(5);
        log.info("query data: {}", JSONUtil.parse(userMenus));
    }
}
