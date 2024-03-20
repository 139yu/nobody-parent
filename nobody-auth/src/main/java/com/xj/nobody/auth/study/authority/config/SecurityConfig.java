package com.xj.nobody.auth.study.authority.config;

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.UrlAuthorizationConfigurer;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("admin").roles("ADMIN").password("{noop}123")
                .and().withUser("test").authorities("test").password("{noop}123")
                .and().withUser("user").roles("USER").password("{noop}123");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                //必须具备ADMIN角色才能访问
                .antMatchers("/auth/admin/**").hasRole("ADMIN")
                //具备ADMIN或者USER角色才能访问
                .antMatchers("/auth/user/**").access("hasAnyRole('ADMIN','USER')")
                //拥有test权限才能访问
                .antMatchers("/auth/test/**").hasAnyAuthority("test")
                .antMatchers("/auth/customer/**").access("isAuthenticated() and permissionExpression.check(httpServletRequest)")
                .antMatchers("/auth/system/**").access("isAuthenticated() and permissionExpression.checkId(authentication,#userId)")
                //其余请求认证后才能访问
                .anyRequest().access("isAuthenticated()")
                .and().formLogin().and().csrf().disable();

    }

    @Bean
    RoleHierarchy roleHierarchy(){
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");
        return hierarchy;
    }
}
