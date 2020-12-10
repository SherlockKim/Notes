# Springboot整合Spring Security

## 简介

Spring 是一个非常流行和成功的 Java 应用开发框架。Spring Security 基于 Spring 框架，提供了一套 Web 应用安全性的完整解决方案。一般来说，Web 应用的安全性包括用户认证（Authentication）和用户授权（Authorization）两个部分。用户认证指的是验证某个用户是否为系统中的合法主体，也就是说用户能否访问该系统。用户认证一般要求用户提供用户名和密码。系统通过校验用户名和密码来完成认证过程。用户授权指的是验证某个用户是否有权限执行某个操作。在一个系统中，不同用户所具有的权限是不同的。比如对一个文件来说，有的用户只能进行读取，而有的用户可以进行修改。一般来说，系统会为不同的用户分配不同的角色，而每个角色则对应一系列的权限。

对于上面提到的两种应用情景，Spring Security 框架都有很好的支持。在用户认证方面，Spring Security 框架支持主流的认证方式，包括 HTTP 基本认证、HTTP 表单验证、HTTP 摘要认证、OpenID 和 LDAP 等。在用户授权方面，Spring Security 提供了基于角色的访问控制和访问控制列表（Access Control List，ACL），可以对应用中的领域对象进行细粒度的控制。





## 认识Spring Security

Spring Security 是针对Spring项目的安全框架，也是Spring Boot底层安全模块默认的技术选型，他可以实现强大的Web安全控制，对于安全控制，我们仅需要引入 spring-boot-starter-security 模块，进行少量的配置，即可实现强大的安全管理！

**重点这三个类：**

- WebSecurityConfigurerAdapter：自定义配置Security策略
- AuthenticationManagerBuilder：自定义认证策略
- @EnableWebSecurity：开启WebSecurity模式



**Spring Security的两个主要目标是 “认证” 和 “授权”（访问控制）**：

* **“认证”（Authentication）**

  身份验证是关于验证您的凭据，如用户名/用户ID和密码，以验证您的身份。身份验证通常通过用户名和密码完成，有时与身份验证因素结合使用。



*  **“授权” （Authorization）**

  授权发生在系统成功验证您的身份（角色）后，最终会授予您访问资源（如信息，文件，数据库，资金，位置，几乎任何内容）的完全权限。





## 整合步骤

### 1.导入依赖

~~~xml
 <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
 </dependency>
~~~



### 2. Controller跳转和页面准备

![image-20201123121044901](C:\Users\鸭屮\AppData\Roaming\Typora\typora-user-images\image-20201123121044901.png)



~~~ java
@Controller
public class LoginController {

    @RequestMapping({"/","/index"})
    public String index(){
        return "index";
    }

    @RequestMapping("toLogin")
    public String toLogin(){
        return "views/login";
    }

    @RequestMapping("/level1/{id}")
    public String level1(@PathVariable("id")int id){
        return "views/level1/"+id;
    }

    @RequestMapping("/level2/{id}")
    public String level2(@PathVariable("id") int id){
        return "views/level2/"+id;
    }

    @RequestMapping("/level3/{id}")
    public String level3(@PathVariable("id") int id){
        return "views/level3/"+id;
    }

}
~~~





### 3.自定义Security策略

配置security config类

~~~ java
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    //自定义授权规则
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //链式编程
        http.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");

        // 开启自动配置的登录功能
        // /login 请求来到登录页
        // /login?error 重定向到这里表示登录失败
        http.formLogin().loginPage("/toLogin").loginProcessingUrl("/login");

        //注销
        http.logout().logoutSuccessUrl("/");

        http.csrf().disable();
        //记住我
        http.rememberMe().rememberMeParameter("remember");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("kim").password(new BCryptPasswordEncoder().encode("123")).roles("vip1", "vip2")
                .and().withUser("root").password(new BCryptPasswordEncoder().encode("123")).roles("vip1", "vip2", "vip3")
                .and().withUser("heimei").password(new BCryptPasswordEncoder().encode("123")).roles("vip1");
    }
}
~~~

* @EnableWebSecurity作用（看源码）：
  1. 加载了WebSecurityConfiguration配置类, 配置安全认证策略。
  2. 加载了AuthenticationConfiguration, 配置了认证信息。



* http.authorizeRequests()：配置路径拦截，设置访问的对应的权限，角色，认证信息。

  

* formLogin()：

  1. loginPage("/toLogin")：请求到登录页面
  2. loginProcessingUrl：登录提交表单的处理数据url



* logout()  注销：
  1. logoutSuccessUrl：注销成功跳转的页面



* rememberMe() 记住我：
  1. rememberMeParameter("remember")：获取（配置）页面的记住我标签的值









# Springboot整合Shiro

## 步骤

### 1.导入依赖

~~~xml
<dependency>
            <groupId>org.apache.shiro</groupId>
            <artifactId>shiro-spring</artifactId>
            <version>1.5.3</version>
     </dependency>

<dependency>
            <groupId>com.github.theborakompanioni</groupId>
            <artifactId>thymeleaf-extras-shiro</artifactId>
            <version>2.0.0</version>
        </dependency>
~~~



### 2.简单写service层，pojo层

~~~ java
//pojo层
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {
    private int id;
    private String username;
    private String password;
    private String role;
}


//service层
@Service
public class UserServiceImpl implements UserService{

    @Autowired
    private UserMapper userMapper;

    @Override
    public List<User> getAll() {
        return userMapper.getUsers();
    }

    @Override
    public User getByName(String username) {
        return userMapper.getUser(username);
    }
}

~~~



### 3.配置shiro文件

~~~ java
@Configuration
public class ShiroConfig {

    //ShiroFilterFactoryBean
    @Bean
    public ShiroFilterFactoryBean getShiroFilterFactoryBean(@Qualifier("securityManager") DefaultWebSecurityManager securityManager) {
        ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
        bean.setSecurityManager(securityManager);
       
        LinkedHashMap<String, String> filterMap = new LinkedHashMap<>();
        filterMap.put("/user/add","perms[user:add]");
        filterMap.put("/user/update","perms[user:update]");
//        filterMap.put("/user/update","authc");
        bean.setFilterChainDefinitionMap(filterMap);

        //登录请求
        bean.setLoginUrl("/toLogin");

        //没有权限时跳转的页面
        bean.setUnauthorizedUrl("/notAuth");
        return bean;
    }

    //DefaultWebSecurityManager
    @Bean(name = "securityManager")
    public DefaultWebSecurityManager getDefaultWebSecurityManager(@Qualifier("userRealm") UserRealm userRealm) {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        //关联自定义的Realm
        securityManager.setRealm(userRealm);
        return securityManager;
    }


    //创建自定义Reaml
    @Bean
    public UserRealm userRealm() {
        return new UserRealm();
    }

    //shiro整合thymeleaf使用
    @Bean
    public ShiroDialect getShiroDialect(){
        return new ShiroDialect();
    }
}

~~~

****



### 4.自我总结

**创建shiro过滤器工厂：ShiroFilterFactoryBean，再传入已配置好的DefaultWebSecurityManager，然后又将自己已自定义的realm策略关联进SecurityManager里。==三个类的关系层层递进！（步骤大致是死的）==**



bean.setFilterChainDefinitionMap(filterMap)：添加shiro内置过滤器      

*  anon：无需认证即可访问
* authc：必须认证后才能访问
* user：必须拥有记住我功能才能访问
* perms：拥有对某资源的权限才能访问
*  role：拥有某个角色的权限才能访问
          

和shiro大同小异的功能：

 bean.setLoginUrl  设置登录跳转url

 bean.setUnauthorizedUrl     当没有权限时跳转的url



**总结：**

![IMG_0270(20201123-194703)](D:\学习项目\框架学习\shiro\IMG_0270(20201123-194703).PNG)

![QQ图片20201125151435](D:\学习项目\框架学习\shiro\QQ图片20201125151435.jpg)

* 自定义的Realm：重写了doGetAuthorizationInfo和doGetAuthenticationInfo的方法，即授权和认证。可以==通过数据库认证用户输入的信息==（用户信息在subject里），和==从数据库授权给用户==。

* ShiroConfig配置文件：创建shiro过滤器工厂，对资源的设置认证信息，授权信息或角色信息等，然后关联DefaultWebSecurityManager类。
* DefaultWebSecurityManager类：关联自定义的Realm
* 创建自定义的Realm
* Controller层：SecurityUtils.getSubject获取Subject实体后，传入用户数据。





