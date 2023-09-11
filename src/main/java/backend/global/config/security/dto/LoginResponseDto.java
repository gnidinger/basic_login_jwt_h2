package astarmize.global.config.security.dto;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

import astarmize.global.config.security.userDetails.AuthUser;
import lombok.Builder;
import lombok.Getter;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class LoginResponseDto {

    @Getter
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class ResponseDto { // 일반 로그인 response

        private Long seq;
        // private String userId;
        private String name;
        private String token;
        private Long expireTime;

        public static ResponseDto of(AuthUser authUser){
            return ResponseDto.builder()
                    .seq(authUser.getSeq())
                    // .userId(authUser.getUserId())
                    .name(authUser.getName())
                    .build();
        }
    }
}
