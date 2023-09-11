package astarmize.domain.user.service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import astarmize.domain.user.entity.User;
import astarmize.domain.user.entity.enums.AuthType;
import astarmize.domain.user.repository.UserRepository;
import astarmize.global.config.PBKDF2Encoder;
import astarmize.global.error.exception.BusinessException;
import astarmize.global.error.exception.ExceptionCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@Service
@RequiredArgsConstructor
public class LoginService {

	private final PBKDF2Encoder pbkdf2Encoder;
	private final UserService userService;
	private final UserRepository userRepository;

	@Transactional
	public User login(User user) {

		User findUser = userService.findByUserId(user.getUserId());
		if (findUser.getPassword().equals(pbkdf2Encoder.encode(user.getPassword()))) {
			return findUser;
		} else {
			throw new BusinessException(ExceptionCode.UNAUTHORIZED);
		}
	}

	@Transactional(readOnly = true)
	public User findUserById(Long id) {
		return null;
	}

	@Transactional(readOnly = true)
	public boolean verifyNickname(String nickname) {
		return true;
	}

	@Transactional
	public void updateNickName(String nickname) {
	}

	@Transactional(readOnly = true)
	public boolean verifyPassword(String nickname) {
		return true;
	}

	@Transactional
	public void updatePassword(String password) {

	}

	@Transactional
	public User updateUserInfo(User user) {
		return null;
	}

	@Transactional
	public boolean deleteUser() {
		return true;
	}

	@Transactional
	public void logout(String refreshToken, HttpServletRequest request, HttpServletResponse response) {

	}

}
