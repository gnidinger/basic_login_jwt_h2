package astarmize.domain.user.controller;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import astarmize.domain.user.entity.User;
import astarmize.domain.user.mapper.UserMapper;
import astarmize.domain.user.service.LoginService;
import astarmize.domain.user.service.UserService;
import astarmize.global.config.security.dto.LoginRequestDto;
import astarmize.global.config.security.dto.LoginResponseDto;
import astarmize.global.config.security.filter.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Validated
@RestController
@RequestMapping("/api/login")
@RequiredArgsConstructor
public class LoginController {

	private final UserMapper userMapper;
	private final LoginService loginService;
	private final JwtTokenProvider jwtTokenProvider;

	@Value("${jwt.token.expiration-minutes}")
	private long expireTime;

	@PostMapping
	public ResponseEntity<LoginResponseDto.ResponseDto> login(@Valid @RequestBody LoginRequestDto.PostDto loginRequestDto) {
		User loggedInUser = loginService.login(userMapper.loginRequestToUser(loginRequestDto));
		LoginResponseDto.ResponseDto responseDto = LoginResponseDto.ResponseDto.builder()
			.seq(loggedInUser.getSeq())
			.name(loggedInUser.getName())
			.token(jwtTokenProvider.createToken(loggedInUser.getName()))
			.expireTime(expireTime)
			.build();
		return ResponseEntity.ok().body(responseDto);
	}
}
