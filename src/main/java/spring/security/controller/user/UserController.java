package spring.security.controller.user;


import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import spring.security.domain.Account;
import spring.security.domain.AccountDto;
import spring.security.service.UserService;

@RequiredArgsConstructor
@Controller
public class UserController {

	private final PasswordEncoder passwordEncoder;
	private final UserService userService;

	@GetMapping(value="/mypage")
	public String myPage() throws Exception {
		return "user/mypage";
	}

	@GetMapping("/users")
	public String createUser() throws Exception {
		return "user/login/register";
	}

	@PostMapping("/users")
	public String createUser(@ModelAttribute AccountDto accountDto) throws Exception {
		ModelMapper modelMapper = new ModelMapper();
		Account account = modelMapper.map(accountDto, Account.class);
		account.setPassword(passwordEncoder.encode(account.getPassword())); //암호화
		userService.createUser(account);

		return "redirect:/";
	}
}
