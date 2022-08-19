package spring.security.security.common;


import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.net.http.HttpRequest;

@Component
public class FormAuthenticationDetailsSource implements AuthenticationDetailsSource <HttpServletRequest, FormWebAuthenticationDetails> {

    @Override
    public FormWebAuthenticationDetails buildDetails(HttpServletRequest context) {
        return new FormWebAuthenticationDetails(context);
    }
}
