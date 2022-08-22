package spring.security.security.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import spring.security.security.filter.AjaxLoginProcessingFilter;
import spring.security.security.handler.AjaxAuthenticationFailureHandler;
import spring.security.security.handler.AjaxAuthenticationSuccessHandler;
import spring.security.security.handler.FormAccessDeniedHandler;

@Configuration
public class CustomMyConfig {

    @Bean
    public PasswordEncoder passwordEncoder(){ //순환참조가 생겨서 옮김
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler(){
        FormAccessDeniedHandler accessDeniedHandler = new FormAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied");
        return accessDeniedHandler;
    }
}
