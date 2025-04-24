package com.jwt_code_practice.domain.member.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Valid
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class SignupRequest {
	/**
	 * 이메일
	 */
	@NotBlank
	@Email
	private String email;
	/**
	 * 비밀번호
	 */
	@NotBlank
	@Size(min = 8)
	@Pattern(regexp = ".*[!@#$%^&*(),.?\":{}|<>].*")
	private String password;
	/**
	 * 닉네임
	 */
	@NotBlank
	@Size(max = 10)
	private String name;
	/**
	 * 전화번호
	 */
	@NotBlank
	@Pattern(regexp = "^(010\\d{8}|011\\d{7})$",
		message = "전화번호는 대시없이 입력하셔야 합니다.")
	private String phone;
}
