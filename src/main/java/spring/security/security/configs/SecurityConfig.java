package spring.security.security.configs;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import spring.security.security.provider.CustomAuthenticationProvider;
import spring.security.security.service.CustomUserDetailsService;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//
//        String password = passwordEncoder().encode("1111");
//
//        auth.inMemoryAuthentication().withUser("user").password(password).roles("USER"); //noop는 prefix형태로 사용 알고리즘을 지정.
//        auth.inMemoryAuthentication().withUser("manager").password(password).roles("MANAGER"); //noop는 prefix형태로 사용 알고리즘을 지정.
//        auth.inMemoryAuthentication().withUser("admin").password(password).roles("ADMIN"); //noop는 prefix형태로 사용 알고리즘을 지정.
//    }

    //private final UserDetailsService userDetailsService;
    private final CustomAuthenticationProvider customAuthenticationProvider;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //auth.userDetailsService(userDetailsService);
        auth.authenticationProvider(customAuthenticationProvider);
    }

    //js css image 등 보안 필터를 적용할 필요가 없는 리소스를 설정. 즉 여기 설정된 것은 아예 보안 필터를 거치지 않고 통과된다. 보안 필터의 범위 밖
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/", "/users").permitAll()  //이건 보안필터의 검사는 받는다.
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated()
                .and()
                .formLogin();


        http
                .csrf();
    }


}
