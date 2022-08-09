package spring.security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity //여러 보안 설정 클래스들을 사용
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated();

        http.formLogin()
                //.loginPage("/loginPage")
                .defaultSuccessUrl("/")
                .failureUrl("/login")
                .usernameParameter("userID")
                .passwordParameter("passwd")
                .loginProcessingUrl("/login-proc")
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication.getName() = " + authentication.getName());
                        response.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception.getMessage() = " + exception.getMessage());
                        response.sendRedirect("/login");
                    }
                })
                .permitAll();

        http.logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
                //.deleteCookies("JESSIONID", "remember-me")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me");

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