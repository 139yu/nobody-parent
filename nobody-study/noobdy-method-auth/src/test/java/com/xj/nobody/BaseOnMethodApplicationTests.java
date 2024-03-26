package com.xj.nobody;

import com.xj.nobody.entity.User;
import com.xj.nobody.service.HelloService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.ArrayList;
import java.util.List;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = NobodyMethodAuthApplication.class)
public class BaseOnMethodApplicationTests {

    @Autowired
    private HelloService helloService;

    @Test
    @WithMockUser(roles = "ADMIN",username = "admin")
    public void preAuthorizeTest() {
        System.out.println(helloService.hello("nobody"));
    }

    @Test
    @WithMockUser(roles = "ADMIN",username = "admin")
    public void preFilterTest(){
        List<User> userList = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            userList.add(new User(i,"nobody"+i,"123456"));
        }
        helloService.addUser(userList, userList.size());
    }
    @Test
    @WithMockUser(roles = "ADMIN",username = "admin")
    public void testPostAuthorize(){
        helloService.getUser(2);
    }

    @Test
    @WithMockUser(roles = "ADMIN",username = "admin")
    public void testPostFilter(){
        List<User> allUser = helloService.getAllUser();
        for (User user : allUser) {
            System.out.println(user);
        }
    }

    @Test
    @WithMockUser(roles = "USER",username = "nobody")
    public void testSecured(){
        helloService.getUserByUsername("nobody");
    }
    @Test
    @WithMockUser(roles = "USER",username = "nobody")
    public void testDenyAll(){
        helloService.denyAll();
    }

    @Test
    @WithMockUser(roles = {"ADMIN"},username = "nobody")
    public void testRolesAllowed(){
        helloService.rolesAllowed();
    }
}
