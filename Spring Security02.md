## 13.3 基于URL地址的权限管理

基于URL地址的权限管理主要通过FilterSecurityInterceptor来实现。如果配置了基于URL地址的权限管理，FilterSecurityInterceptor会自动添加到Spring Security过滤器链中；

请求被拦截后会交给AccessDecisionManager进行处理。

### 13.3.1基本用法

用户不能同时与角色和权限相关联，在Spring Security提供的User类中，两种方式最终都会调用User#authorities(Collection<? extends GrantedAuthority>)方法，最终后者
会覆盖前者。

示例：
```java
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
                //其余请求认证后才能访问
                .anyRequest().access("isAuthenticated()")
                .and().formLogin().and().csrf().disable();
    }
}
```
注意事项： 

1.hasRole、hasAnyAuthority等方法最终都会转化为表达式

2.可通过access方法来使用权限表达式

3.当请求到达后，会按照从上往下顺序匹配，所以权限配置顺序很重要

### 13.3.2 角色继承

配置角色继承只需要提供RoleHierarchy实例：

```java
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
```

ROLE_ADMIN继承紫ROLE_USER，具备ROLE_USER的权限

### 13.3.3自定义表达式

如下，登录必须为nobody才可访问：
```java
@Component
public class PermissionExpression {
    public boolean check(HttpServletRequest req){
        return "nobody".equals(req.getParameter("username"));
    }
}

```

在SecurityConfig中配置：
```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("admin").roles("ADMIN").password("{noop}123")
                .and().withUser("test").authorities("test").password("{noop}123")
                .and().withUser("user").roles("USER").password("{noop}123");
    }[ja-netfilter.jar](..%2F..%2Fja-netfilter%2Fja-netfilter.jar)

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
                //其余请求认证后才能访问
                .anyRequest().access("isAuthenticated()")
                .and().formLogin().and().csrf().disable();
    }
}
```

### 13.3.4 原理分析 

- AbstractSecurityInterceptor

AbstractSecurityInterceptor统筹着关于权处理的一切，主要方法：beforeInvocation、afterInvocation、finallyInvocation。

- FilterSecurityInterceptor
    
使用基于URL地址的权限管理，此时使用的是AbstractSecurityInterceptor的子类FilterSecurityInterceptor。在configure(HttpSecurity)方法中调用
http.authorizeRequests()开启URL路径拦截规则配置时，就会通过AbstractInterceptUrlConfigurer#configure方法将FilterSevurityInterceptor添加到Spring Security过滤器链中

- AbstractInterceptorUrlConfigurer
    
AbstractInterceptorUrlConfigurer主要用于创建FilterSecurityInterceptor，它有两个子类：ExpressionUrlAuthorizationConfigurer、UrlAuthorizationConfigurer。构建出来的
FilterSecurityInterceptor所使用的投票器和权限影视剧对象不一样，ExpressionUrlAuthorizationConfigurer支持表达式，但至少配置一对URL地址和权限之间的映射关系，UrlAuthorizationConfigurer不支持表达式。
UrlAuthorizationConfigurer配置FilterSecurityInterceptor需要手动创建一个UrlAuthorizationConfigurer：
```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    
    ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
    http
            .apply(new UrlAuthorizationConfigurer<>(applicationContext))
            .getRegistry()
            //角色ROLE前缀必须加上
            .mvcMatchers("/admin/**").access("ROLE_ADMIN")
            .mvcMatchers("/user/**").access("ROLE_USER");
    http.formLogin().and().csrf().disable();
}
```
并且映射关系要确保完整，不然会出错，如下：
```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    
    ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
    http
            .apply(new UrlAuthorizationConfigurer<>(applicationContext))
            .getRegistry()
            .mvcMatchers("/admin/**").access("ROLE_ADMIN")
            .mvcMatchers("/user/**");
    http.formLogin().and().csrf().disable();
}
```

### 13.3.5 动态管理权限规则

模块：`nobody-study/nobody-dynamic-auth`

## 13.4基于方法的权限管理

### 13.4.1注解介绍

通过@EnableGlobalMethodSecurity注解开启权限注解的使用：

```java
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true,securedEnabled = true,jsr250Enabled = true)
public class SecurityConfig {
}
```
注解属性介绍：

- prePostEnabled：开启Spring Security提供的四个权限注解，@PreAuthorize、@PostAuthorize、@PreFilter、@PostFilter
- securedEnabled：开启Spring Security提供的两个权限注解，@Secured，不支持权限表达式
- jsr250Enabled：开启JSR-250提供的权限注解，主要包括@RolesAllowed、@DenyAll、@PermitAll，不支持权限表达式

注解介绍：

- @PreAuthorize：在目标方法之前之后进行权限校验
- @PostFilter：在目标方法执行之后对返回结果进行过滤
- @PreAuthorize：在目标方法之前进行权限校验
- @PreFilter：在目标方法执行之前对参数进行过滤
- @Secured：访问目标方法必须具备相应的角色
- @DenyAll：拒绝所有访问
- @PermitAll：允许所有访问
- @RolesAllowed：访问目标方法必须具备相应的角色

一般`prePostEnable=true`够用

### 13.4.2基本用法

- @PreAuthorize示例
- 
```java
@Service
public class HelloService {
    @PreAuthorize("hasRole('ADMIN') and authentication.name==#username")
    public String hello(String username){
        return "hello";
    }
}
```
通过`#`可以引用方法的参数

- PreFilter示例

```java
@Service
public class HelloService {
    @PreFilter(value = "filterObject.id%2!=0",filterTarget = "users")
    public void addUser(List<User> users, Integer other){
        for (User user : users) {
            System.out.println(user);
        }
    }
}
```
filterObject是一个内置对象，filterTarget是过滤的目标对象，如果方法只有一个参数，filterObject就代表这参数，如果有多个，需要通过filterTarget指定

这里只会打印id为奇数的用户

- @PostAuthorize示例

```java
@Service
public class HelloService {
    @PostAuthorize("returnObject.id==1")
    public User getUser(Integer id){
        return new User(id,"admin","123456");
    }
}
```
返回的id必须为1，否则抛出异常；此注解在ACL权限模型中会用到

- @PostFilter示例

```java
public class HelloService {
@PostFilter("filterObject.id%2!=0")
    public List<User> getAllUser(){
        List<User> list = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            list.add(new User(i,"admin"+i,"123456"));
        }
        return list;
    }
}
```
效果同@PreFilter

- @Secured示例

```java
public class HelloService {
    //表示用户需要具备ROLE_ADMIN,ROLE_USER两个角色才能访问
    @Secured({"ROLE_ADMIN", "ROLE_USER"})
    public User getUserByUsername(String username) {
        return new User(1, "admin", "123456");
    }
}
```
@Secured不支持权限表达式

- @RolesAllowed示例

```java
public class HelloService {
    @RolesAllowed({"ADMIN","USER"})
    public String rolesAllowed(){
        return "rolesAllowed";
    }
}
```
RolesAllowed是jsr-250提供的注解，可以添加方法上，也可添加在类上，添加在类上对所有方法都有效，如果类上和方法上都有，则以方法上的注解为准

### 13.4.3原理剖析

基于Url请求地址进行权限控制时，AbstractSecurityInterceptor的实现类是FilterSecurityInterceptor，而基于方法进行权限控制时，它的实现类是MethodSecurityInterceptor。

- @EnableGlobalMethodSecurity注解

```java
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
@Documented
@Import({GlobalMethodSecuritySelector.class})
@EnableGlobalAuthentication
@Configuration
public @interface EnableGlobalMethodSecurity {
}
```
GlobalMethodSecuritySelector负责导入配置类

关键对象：MethodSecurityMetadataSource，MethodSecurityInterceptor

# 14.权限模型

## 14.1RBAC

### 14.1.1介绍

RBAC（Role-based access control）是一种以角色为基础的访问控制，这种机制不将权限直接赋予用户，而是将权限赋予角色

RBAC权限模型原则：

1. 最小权限：给角色配置的权限是其完成任务所需要的最小权限集合

2. 职责分离：通过相互独立互斥的角色来共同完成任务

3. 数据抽象：通过权限的抽象来体现，RBAC支持的数据抽象程度与RBAC的实现细节有关

### RBAC权限模型分类

- RBAC0

最简单的用户、角色、权限模型

- RBAC1

在RBAC0的基础上增加了角色继承

- RBAC2

也是在RBAC0的基础上拓展，引入了静态职责分离和动态职责分离；要理解职责分离，得先理解角色互斥；例如财务角色一般不能和其他角色兼任，否则自己报账自己审批，通过职责分离可以解决此问题

静态职责分离：在权限配置阶段就做限制

动态职责分离：在运行阶段做限制

- RBAC3

RBAC3是RBAC1和RBAC2的合体

# 15.OAuth2

## 15.1.OAuth2介绍

OAuth是一个开放标准，该标准允许让第三方应用访问该用户在某一网站上存储的私密资源，并且在这个过程中无须将用户名密码提供给第三方。通过
令牌可以实现这一功能，每一个令牌授权一个特定的网站在特定的时间段内运行访问特定的资源。

OAuth2是OAuth的下一个版本，但不兼容OAuth1.0。

## 15.2.OAuth2授权模式

OAuth2一共支持四种不同的授权模式：

1. 授权码模式：常见第三方平台都使用这种模式

2. 简化模式：不需要第三方服务端参与，直接在浏览器中向授权服务器申请令牌，适用于纯静态页面

3. 密码模式：将用户名/密码告诉客户端，客户端使用这些信息向授权服务器申请令牌

4. 客户端模式：客户端使用自己的名义而不是用用户的名义向服务提供提供者申请授权

授权流程：
![](/asset/CmQUOWCPmgaEfSVOAAAAAOkkuEo422410948.jpg)

OAuth2包含四种不同角色：

- Client：第三方应用

- Resource Owner：资源所有者

- Authorization Server：授权服务器

- Resource Server：资源服务器

### 15.2.1授权码模式

假设给www.xxx.com，引入github第三方登录功能，www.xxx.com大于一个第三方应用，选择使用github登录时，就会去请求授权服务器（GitHub的授权服务器），www.xxx.com首页的登录超链接可能如下：
```http request
https://github.com/oauth/authorize?response_type=code&client_id=xxx&redirect_uri=www.xxx.com&scope=all&state=123
```
参数说明：

- response_type：授权类型，code表示授权方式为授权码模式，拿到授权码之后再根据授权码去获取Access Token

- client_id：客户端id，第三方应用id

- redirect_uri：登录成功/失败后跳转的地址。跳转的时候会携带授权码参数，可发者再根据这个参数获取Access Token

- scope：授权范围

- state：授权服务器会原封不动的返回该参数，通过对该参数校验，可以防止CSRF攻击

## 15.3.GitHub授权登录

准备工作：在GitHub上创建一个应用，配置应用地址，回调地址（相当于登录请求链接），并获取client_id和client_secret

### 15.3.1项目开发

创建一个Spring Boot项目，引入Web、Spring Security以及OAuth2 Client依赖：
```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-oauth2-client</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
</dependencies>
```

提供测试接口：
```java
@RestController
@RequestMapping("test")
public class TestController {
    @GetMapping("hello")
    public DefaultOAuth2User hello(){
        return (DefaultOAuth2User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }
}
```
创建配置类：
```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated()
                .and().oauth2Login();
    }
}
```
配置文件：
```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          github:
            client-id: Iv1.7b0677047c106da2
            client-secret: 13448ed583e1fa74bbb4bc04055c19ecc8be9690
server:
  port: 9001
```
至此就可以使用GitHub登录了

### 15.3.2原理分析

由于用户接口、令牌接口、授权地址等信息一般不会轻易变化，所以Spring Security使用CommonOAuth2Provider枚举类收集了一些常用的第三方登录信息

开启OAuth2自动登录之后，Spring Security会添加两个过滤器：OAuth2AuthorizationRequestRedirectFilter，OAuth2LoginAuthenticationFilter。
当用户未登录访问`http://localhost:9001/test/hello` 时，会被自动导入GitHub的授权页面，这是由OAuth2AuthorizationRequestRedirectFilter实现的；GitHub登录成功后，会
调用回调地址，返回授权码，客户端再根据授权码去GitHub授权服务器上获取Access Token，这个过程是由OAuth2LoginAuthenticationFilter完成的

回调地址：
```http request
http://localhost:9001/login/oauth2/code/github?code=53db0b39876520afc426&state=CvAM6Ytiq7S7_v2Vz8TDzx5_cwhVOc73HchsqHJoZJU%3D
```

- OAuth2ClientRegistrationRepositoryConfiguration

该类是一个配置类，项目启动时该类会自动加载，该类只有一个clientRegistrationRepository方法，参数OAuth2ClientProperties包含的信息就是就是授权服务信息，如Client Id，Client Secret等，
可配置多个授权服务器

- OAuth2AuthorizationRequestRedirectFilter

该过滤器主要用于判断当前请求是否是授权请求，如果是则重定向到GitHub授权页面

- OAuth2LoginAuthenticationFilter

GitHub授权服务器登录成功后的回调地址是`http://localhost:9001/login/oauth2/code/github`，但是项目中并没有定义这样一个接口，能调用成功就是OAuth2LoginAuthenticationFilter
起作用了，该该类定义了默认的回调uri：
```java
public static final String DEFAULT_FILTER_PROCESSES_URI = "/login/oauth2/code/*";
```
OAuth2LoginAuthenticationFilter的功能相当于UsernamePasswordAuthenticationFilter。
```java
public abstract class AbstractAuthenticationProcessingFilter extends GenericFilterBean
		implements ApplicationEventPublisherAware, MessageSourceAware {
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        //省略
        if (!requiresAuthentication(request, response)) {
            chain.doFilter(request, response);
            return;
        }
        //省略
    }
    
}
```
如果使用了OAuth2登录，这里的逻辑就是判断当前请求是否是`/login/oauth2/code/*`格式，如果是则交由OAuth2LoginAuthenticationFilter处理，不是则交由下一个过滤器处理。
后面认证使用AuthenticationProvider实例是OAuth2LoginAuthenticationProvider

- OAuth2LoginAuthenticationProvider

通过授权码获取Access Token的工作就是在此类中完成的

### 15.3.3自定义配置

#### 15.3.3.1自定义ClientRegistrationRepository

如果回调地址不是默认的`/login/oauth2/code/*`格式，可通过修改yml配置文件修改：
```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          github:
            client-id: Iv1.7b0677047c106da2
            client-secret: 13448ed583e1fa74bbb4bc04055c19ecc8be9690
            redirect-uri: http://localhost:9001/authorizetion_code
```
然后修改认证请求处理地址：
```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated()
                .and().oauth2Login();
    }
}
```
除了使用yml配置，也可使用java类配置，使用java类配置时删除yml中关于OAuth2的配置：
```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated()
                .and().oauth2Login().loginProcessingUrl("/authorization_code");
    }
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(){
        return new InMemoryClientRegistrationRepository(githubClientRegistration());
    }
    private ClientRegistration githubClientRegistration(){
        return ClientRegistration.withRegistrationId("github")
                .clientId("Iv1.7b0677047c106da2")
                .clientSecret("13448ed583e1fa74bbb4bc04055c19ecc8be9690")
                .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                .userNameAttributeName("id")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUriTemplate("http://localhost:9001/authorization_code")
                .scope("read:user")
                .authorizationUri("https://github.com/login/oauth/authrize")
                .tokenUri("https://github.com/login/oauth/access_token")
                .userInfoUri("https://api.github.com/user")
                .clientName("GitHub")
                .build()
                ;
    }
}
```

#### 15.3.3.2自定义用户
默认情况GitHub返回的用户信息被包装成DefaultOauth2User对象，但是用户信息是使用Map集合保存，自定义用户对象需要实现OAuth2User接口：
```java
public class CustomerOAuth2User implements OAuth2User {
    private List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
    private Map<String, Object> attributes;
    private String id;
    private String name;
    private String email;
    private String login;

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getName() {
        return this.name;
    }
    // getter setter
}
```
如果还需映射其他属性，继续定义相应属性即可，最后在配置类中使用该自定义对象：
```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated()
                .and().oauth2Login().userInfoEndpoint().customUserType(CustomerOAuth2User.class,"github")
                .and()
                .loginProcessingUrl("/authorization_code");
    }
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(){
        return new InMemoryClientRegistrationRepository(githubClientRegistration());
    }
    private ClientRegistration githubClientRegistration(){
        return ClientRegistration.withRegistrationId("github")
                .clientId("Iv1.7b0677047c106da2")
                .clientSecret("13448ed583e1fa74bbb4bc04055c19ecc8be9690")
                .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                .userNameAttributeName("id")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUriTemplate("http://localhost:9001/authorization_code")
                .scope("read:user")
                .authorizationUri("https://github.com/login/oauth/authrize")
                .tokenUri("https://github.com/login/oauth/access_token")
                .userInfoUri("https://api.github.com/user")
                .clientName("GitHub")
                .build()
                ;
    }
}
```
配置完成后通过Access Token去加载用户信息时将不再使用DefaultOAuth2UserService，而是使用CustomerUserTypesOAuth2UserService

## 15.4资源服务器与授权服务器

授权服务器模块：`nobody-study/nobody-auth-server`

资源服务器模块：`nobody-study/nobody-resource-server`

客户端应用：`nobody-study/nobody-auth-client`

### 15.4.1原理分析

- 资源服务器 

资源服务器配置了`.oauth2ResourceServer().opaqueToken()`之后，会向Spring Security过滤器链中添加BearerTokenAuthenticationFilter过滤器，
在该过滤器中完成令牌的解析与校验
  
- 客户端

客户端的请求通过WebClient发起，底层发起HTTP请求的依旧是RestTemplate。有WebClient发起的请求会被DefaultOAuth2AuthorizedClientManager，在
此类的authorize方法，调用对应的OAuth2AuthorizedClientProvider对请求授权