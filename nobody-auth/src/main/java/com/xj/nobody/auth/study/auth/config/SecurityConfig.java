package com.xj.nobody.auth.study.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

//@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {



    //@Bean
    //@Override
    //public AuthenticationManager authenticationManagerBean() throws Exception {
    //    ProviderManager providerManager = new ProviderManager(captchaAuthenticationProvider());
    //    return providerManager;
    //}

    ///**
    // * 指定自定义userDetailService，需要实现UserDetailsService接口
    // * @param
    // * @throws Exception
    // */
    //@Override
    //protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    //}

    //@Override
    //public void configure(WebSecurity web) throws Exception {
    //    web.ignoring().antMatchers("/login.html","/css/**", "/static/**","images/**");
    //}

    /**
     * successForwardUrl和defaultSuccessUrl的区别：
     *  1.defaultSuccessUrl表示当前用户登录成功之后，会自动重定向到登陆之前的地址上，如果用户本身就是直接访问的登录页面，则登录成功后会重定向到defaultSuccessUrl指定的页面中
     *  2.successForwardUrl则不会考虑用户之前的访问地址，只要用户登录成功，就会通过服务端跳转到successForwardUrl锁指定的地址
     * 在前后端分离开发中，用户登录成功之后不需要返回页面，只需返回json数据，可通过自定义AuthenticationSuccessHandler的实现类来完成,同样的登录失败可通过自定义AuthenticationFailureHandler的实现类来完成
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        InMemoryUserDetailsManager userDetailsManager = new InMemoryUserDetailsManager();
        userDetailsManager.createUser(User.withUsername("javaBoy").password("{noop}123456").roles("admin").build());
        http
                //开启权限配置
                .authorizeRequests()
                .anyRequest().authenticated()

                //and从新一轮配置
                .and()
                .formLogin()
                //.withObjectPostProcessor(new ObjectPostProcessor<UsernamePasswordAuthenticationFilter>() {
                //    @Override
                //    public <O extends UsernamePasswordAuthenticationFilter> O postProcess(O object) {
                //        object.setUsernameParameter("uname");
                //        object.setPasswordParameter("passwd");
                //        object.setAuthenticationSuccessHandler((req,resp,auth) -> {
                //            resp.getWriter().write("login success");
                //        });
                //        return object;
                //    }
                //})
                .loginPage("/login.html")
                .loginProcessingUrl("/doLogin")
                //配置自定义登录成功处理
                //.successHandler(successHandler())
                //successForwardUrl是通过ForwardAuthenticationSuccessHandler来实现的，failureForwardUrl同样有对应的handler
                //.successForwardUrl("")
                //.defaultSuccessUrl("")
                //指定form表单提交的密码参数名
                //.passwordParameter("passwd")
                //指定form表单提交的账号参数名
                //.usernameParameter("uname")
                .failureUrl("/error.html")
                //permitAll表示不对以上接口拦截
                .permitAll()
                .and().logout()
                //.logoutRequestMatcher(new OrRequestMatcher(
                //        new AntPathRequestMatcher("/logout1","GET"),
                //        new AntPathRequestMatcher("/logout2","POST")
                //))
                ////表示是否是session失效，默认为true
                .invalidateHttpSession(true)
                //.logoutSuccessHandler((req, resp, auth) -> {
                //    resp.setContentType("application/json");
                //    resp.setStatus(200);
                //    Map<String,Object> result = new HashMap<>();
                //    result.put("msg","success");
                //    PrintWriter writer = resp.getWriter();
                //    ObjectMapper om = new ObjectMapper();
                //    writer.write(om.writeValueAsString(result));
                //})
                //.defaultLogoutSuccessHandlerFor((req,resp,auth) -> {
//
                //},new AntPathRequestMatcher("/logout1","GET"))
                //.defaultLogoutSuccessHandlerFor((req,resp,auth) -> {
//
                //},new AntPathRequestMatcher("/logout2","POST"))
                ////表示是否清除认证信息，默认为true
                .clearAuthentication(true)
                ////注销登录后的跳转地址
                //.logoutSuccessUrl("")
                .and().userDetailsService(userDetailsManager).csrf().disable()



        ;


    }

    /**
     * 自定义登录成功处理
     * HttpSecurity.defaultSuccessUrl就是通过设置SavedRequestAwareAuthenticationSuccessHandler的属性来实现的
     * @return
     */
    SavedRequestAwareAuthenticationSuccessHandler successHandler(){
        SavedRequestAwareAuthenticationSuccessHandler handler = new SavedRequestAwareAuthenticationSuccessHandler();
        handler.setTargetUrlParameter("target");
        handler.setDefaultTargetUrl("/index");
        return handler;
    }

    //@Bean
    //AuthenticationProvider captchaAuthenticationProvider(){
    //    CaptchaAuthenticationProvider provider = new CaptchaAuthenticationProvider();
    //    //TODO 设置数据源
    //    //provider.setUserDetailsService(数据源);
    //    return provider;
    //}

    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

}
