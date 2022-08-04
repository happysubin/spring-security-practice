package spring.security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity //여러 보안 설정 클래스들을 사용
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin();
    }
}


/**
 * 인증, 인가 api를 제공.
 *
 * 그러나 WebSecurityConfigurerAdapter is deprecated 되었다.
 *
 * 그렇다면, Spring Security는 왜 WebSecurityConfigureAdapter를 사용하지 않는 것일까요? 그리고 그 대안은 무엇일까요?
 * Spring 프레임워크의 개발자들은 사용자들이 컴포넌트 기반 보안 구성으로 이동하도록 권장하기 때문입니다.
 * 따라서 WebSecurityConfigureAdapter를 확장하고 HttpSecurity 및 WebSecurity를 구성하는 방법을 재정의하는 대신 SecurityFilterChain 및 WebSecurityCustomizer 유형의 두 콩을 다음과 같이 선언합니다.
 *
 *
 * https://www.codejava.net/frameworks/spring-boot/fix-websecurityconfigureradapter-deprecated
 */