package com.jwt_code_practice.domain.member.dto.response;

import com.jwt_code_practice.domain.member.entity.Member;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SignupResponse {
	private String name;
	private String message;

	public static SignupResponse of(Member member) {
		return SignupResponse.builder()
			.name(member.getName())
			.message(member.getName() + "님의 회원가입을 환영합니다.")
			.build();
	}
}
