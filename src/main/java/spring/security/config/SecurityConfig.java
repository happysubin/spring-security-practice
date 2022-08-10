package spring.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Service;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity //여러 보안 설정 클래스들을 사용
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

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

        http.rememberMe()
                .rememberMeParameter("remember-me") //기본 파라미터는 remember-me
                .tokenValiditySeconds(3600) //초단위로 설정 default는 14일
                //.alwaysRemember(true) //리멤버 미 기능이 활성화되지 않아도 항상 실행
                .userDetailsService(userDetailsService);

        //동시 세션 제어
        http.sessionManagement()
                .maximumSessions(1) //최대 허용 가능 세션 수, -1 설정하면 무제한 로그인 세션 적용
                .maxSessionsPreventsLogin(false); //true면 동시 로그인 차단, false 값을 주면 기존 세션 만료한다. false 여러 사이트에서 많이 사용하는 방법인 듯
                //.invalidSessionUrl("/invalid") //세션이 유효하지 않을 경우 이동하는 페이지
                //.expiredUrl("/expired"); //세션이 만료된 경우 이동하는 페이지

        //세션 고정 보호
        http.sessionManagement()
                .sessionFixation()
                .changeSessionId(); //매번 새로운 세션 아이디를 생. 이게 기본

        //세션 정책
        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED); //기본 값
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