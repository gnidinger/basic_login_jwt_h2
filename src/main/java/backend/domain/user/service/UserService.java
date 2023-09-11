package astarmize.domain.user.service;

import java.util.Optional;

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
public class UserService {

	private final PBKDF2Encoder pbkdf2Encoder;
	private final UserRepository userRepository;

	@Transactional
	public User registerUser(User user) {

		User newUser = User.builder()
			.userId(user.getUserId())
			.name(user.getName())
			.authType(AuthType.ROLE_USER)
			.password(pbkdf2Encoder.encode(user.getPassword()))
			.build();

		userRepository.save(newUser);

		return newUser;
	}

	@Transactional(readOnly = true)
	public User findByUserId(String userId) {
		Optional<User> findUser = userRepository.findByUserId(userId);
		return findUser.orElseThrow(() -> new BusinessException(ExceptionCode.USER_NOT_FOUND));
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
