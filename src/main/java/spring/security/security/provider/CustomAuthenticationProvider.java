package spring.security.security.provider;

import lombok.RequiredArgsConstructor;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import org.springframework.stereotype.Component;
import spring.security.security.service.AccountContext;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {  //authentication 매니저가 보여준 인증객체. 아이디 패스워드가 담겨있.
        String username = authentication.getName();
        String password = (String) authentication.getPrincipal();

        AccountContext accountContext = (AccountContext)userDetailsService.loadUserByUsername(username); //아이디 검증

        if(passwordEncoder.matches(password, accountContext.getAccount().getPassword())){ //비밀번호 인증
            throw new BadCredentialsException("비밀번호 틀림");
        }

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());

        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
