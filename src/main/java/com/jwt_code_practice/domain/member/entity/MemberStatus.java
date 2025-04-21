package com.jwt_code_practice.domain.member.entity;

import lombok.Getter;

/**
 * 사용자 상태를 나타내는 enum class
 * <p>
 *     - ACTIVE: 활성화 <br>
 *     - INACTIVE: 비활성화 <br>
 *     - BLOCKED: 정지 <br>
 *     - DELETED: 탈퇴
 * </p>
 * author sungyeong98
 */
@Getter
public enum MemberStatus {
	ACTIVE("활성화"),
	INACTIVE("비활성화"),
	BLOCKED("정지"),
	DELETED("탈퇴");

	private final String description;

	MemberStatus(String description) {
		this.description = description;
	}
}
