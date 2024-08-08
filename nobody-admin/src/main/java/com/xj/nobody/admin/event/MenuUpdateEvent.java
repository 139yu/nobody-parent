package com.xj.nobody.admin.event;

import com.xj.nobody.admin.enums.MenuEventType;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.springframework.context.ApplicationEvent;

import java.time.Clock;

@Getter
@Setter
public class MenuUpdateEvent extends ApplicationEvent {
    private MenuEventType eventType;
    private Integer menuId;

    public MenuUpdateEvent(Object source) {
        super(source);
    }

    public MenuUpdateEvent(Object source, MenuEventType eventType, Integer menuId){
        super(source);
        this.menuId = menuId;
        this.eventType = eventType;
    }
}
