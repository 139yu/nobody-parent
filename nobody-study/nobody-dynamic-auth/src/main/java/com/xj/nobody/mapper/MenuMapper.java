package com.xj.nobody.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.xj.nobody.entity.Menu;

import java.util.List;

public interface MenuMapper extends BaseMapper<Menu> {
    public List<Menu> getAllMenu();
}
