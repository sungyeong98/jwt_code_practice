package com.jwt_code_practice.domain.member.entity;

import lombok.Getter;

/**
 * 사용자 역할을 나타내는 enum class
 * <p>
 *     - ROLE_USER: 일반 유저 <br>
 *     - ROLE_ADMIN: 관리자
 * </p>
 */
@Getter
public enum MemberRole {
	ROLE_USER("일반 유저"),
	ROLE_ADMIN("관리자");

	private final String description;

	MemberRole(String description) {
		this.description = description;
	}
}
