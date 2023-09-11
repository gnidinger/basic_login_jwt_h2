package astarmize.domain.user.controller;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import astarmize.domain.user.dto.UserDto;
import astarmize.domain.user.entity.User;
import astarmize.domain.user.mapper.UserMapper;
import astarmize.domain.user.service.UserService;
import astarmize.global.config.security.filter.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Validated
@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

	private final UserMapper userMapper;
	private final UserService userService;
	private final JwtTokenProvider jwtTokenProvider;

	@Value("${jwt.token.expiration-minutes}")
	private long expireTime;

	@PostMapping("/register")
	public ResponseEntity<UserDto.RegisterResponse> registerUser(@Valid @RequestBody UserDto.Register registerDto) {
		User savedUser = userService.registerUser(userMapper.registerToUser(registerDto));
		UserDto.RegisterResponse registerResponse = UserDto.RegisterResponse.builder()
			.seq(savedUser.getSeq())
			.name(savedUser.getName())
			.token(jwtTokenProvider.createToken(savedUser.getName()))
			.expireTime(expireTime)
			.build();
		return ResponseEntity.ok().body(registerResponse);
	}
}
