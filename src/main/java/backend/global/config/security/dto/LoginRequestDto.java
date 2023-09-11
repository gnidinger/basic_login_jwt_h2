package astarmize.global.config.security.dto;



import javax.validation.constraints.NotBlank;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;


public class LoginRequestDto {

    @Getter
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    public static class PostDto { // 일반 로그인 request
        @NotBlank(message = "아이디를 입력하셔야 합니다")
        private String userId;
        @NotBlank(message = "패스워드를 입력하셔야 합니다")
        private String password;
    }
}
