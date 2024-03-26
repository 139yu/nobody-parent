package com.xj.nobody.service;

import com.xj.nobody.entity.User;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.stereotype.Service;

import javax.annotation.security.DenyAll;
import javax.annotation.security.RolesAllowed;
import java.util.ArrayList;
import java.util.List;
@RolesAllowed({"ROLE_ROOT"})
@Service
public class HelloService {
    @PreAuthorize("hasRole('ADMIN') and authentication.name==#username")
    public String hello(String username){
        return "hello";
    }

    @PreFilter(value = "filterObject.id%2!=0",filterTarget = "users")
    public void addUser(List<User> users, Integer other){
        for (User user : users) {
            System.out.println(user);
        }
    }

    @PostAuthorize("returnObject.id==1")
    public User getUser(Integer id){
        return new User(id,"admin","123456");
    }

    @PostFilter("filterObject.id%2!=0")
    public List<User> getAllUser(){
        List<User> list = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            list.add(new User(i,"admin"+i,"123456"));
        }
        return list;
    }

    @Secured({"ROLE_ADMIN","ROLE_USER"})
    public User getUserByUsername(String username){
        return new User(1,"admin","123456");
    }
    @DenyAll
    public String denyAll(){
        return "denyAll";
    }
    @RolesAllowed({"ROLE_ADMIN","ROLE_USER"})
    public String rolesAllowed(){
        return "rolesAllowed";
    }
}
