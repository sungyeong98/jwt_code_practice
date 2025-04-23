package com.jwt_code_practice.global.security.dto;

import org.hibernate.validator.constraints.Length;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 로그인 요청 정보를 담는 DTO 클래스
 * <p>
 * 이 클래스는 사용자의 로그인 요청 시 이메일과 비밀번호를 검증하는 역할을 합니다.
 * </p>
 *
 * @author sungyeong98
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {
	/**
	 * 사용자 이메일
	 * <p>
	 * 이메일은 필수 입력 값이며, 올바른 이메일 형식이어야 합니다.
	 * </p>
	 */
	@NotBlank(message = "이메일은 필수입니다.")
	@Email(message = "올바른 이메일 형식이 아닙니다.")
	private String email;

	/**
	 * 사용자 비밀번호
	 * <p>
	 * 비밀번호는 필수 입력 값이며, 8자 이상이어야 하고, 특수문자를 포함해야 합니다.
	 * </p>
	 */
	@NotBlank(message = "비밀번호를 입력해주세요")
	@Length(min = 8, message = "비밀번호는 8자 이상 입력해야 합니다.")
	@Pattern(regexp = ".*[!@#$%^&*(),.?\":{}|<>].*", message = "특수문자를 포함해야 합니다.")
	private String password;
}
