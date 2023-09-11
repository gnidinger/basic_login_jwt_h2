package astarmize.domain.user.mapper;

import org.mapstruct.Mapper;

import astarmize.domain.user.dto.UserDto;
import astarmize.domain.user.entity.User;
import astarmize.global.config.security.dto.LoginRequestDto;

@Mapper(componentModel = "spring")
public interface UserMapper {
	default User registerToUser(UserDto.Register registerDto) {
		return User.builder()
			.userId(registerDto.getUserId())
			.password(registerDto.getPassword())
			.name(registerDto.getName())
			.build();
	}

	default User loginRequestToUser(LoginRequestDto.PostDto loginRequestDto) {
		return User.builder()
			.userId(loginRequestDto.getUserId())
			.password(loginRequestDto.getPassword())
			.build();
	}
}
