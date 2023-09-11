package astarmize.domain.user.dto;

import javax.validation.constraints.Pattern;

import lombok.Builder;
import lombok.Getter;

public class UserDto {

	@Getter
	@Builder
	public static class Register {

		@Pattern(regexp = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", message = "이메일 형식이 맞지 않습니다.")
		String userId;
		@Pattern(regexp = "^[가-힣0-9!@#$%^&*()-_+=<>?]{2,9}$", message = "이름은 문자, 숫자, 특수문자를 포함한 2자 이상 10자 미만이어야 합니다.")
		String name;
		@Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d\\W_]{8,15}$", message = "비밀번호는 숫자, 문자를 포함해 8자리 이상 15자리 이하이어야 합니다.")
		String password;
		@Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d\\W_]{8,15}$", message = "비밀번호는 숫자, 문자를 포함해 8자리 이상 15자리 이하이어야 합니다.")
		String passwordRepeat;
		// String company;
	}

	@Getter
	@Builder
	public static class RegisterResponse {

		private Long seq;
		private String name;
		private String token;
		private Long expireTime;
	}
}
