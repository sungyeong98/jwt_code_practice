package com.jwt_code_practice.domain.member.entity;

import java.io.Serial;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.UUID;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 사용자 엔티티
 * @author sungyeong98 <br>
 * 구성 요소
 * <p>
 *     - id: 고유 ID <br>
 *     - email: 이메일 <br>
 *     - password: 비밀번호 <br>
 *     - name: 이름 <br>
 *     - phone: 전화번호 <br>
 *     - memberRole: 사용자 역할 <br>
 *     - memberStatus: 사용자 상태 <br>
 *     - memberId: 사용자 ID <br>
 *     - uniqueId: 고유 ID <br>
 *     - createdAt: 생성 시간 <br>
 *     - updatedAt: 수정 시간
 * </p>
 */
@Entity
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EntityListeners(AuditingEntityListener.class)
public class Member implements Serializable {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Email
	@NotNull
	private String email;

	@NotNull
	private String password;

	@NotNull
	private String name;

	@NotNull
	private String phone;

	@Column(name = "member_role", nullable = false)
	@Enumerated(EnumType.STRING)
	private MemberRole memberRole;

	@Column(name = "member_status", nullable = false)
	@Enumerated(EnumType.STRING)
	private MemberStatus memberStatus;

	@Column(name = "member_id", nullable = false)
	private String memberId;

	@Column(name = "unique_id", nullable = false)
	private String uniqueId;

	@CreatedDate
	@Column(name = "created_at", nullable = false)
	private LocalDateTime createdAt;

	@LastModifiedDate
	@Column(name = "updated_at", nullable = false)
	private LocalDateTime updatedAt;

	@Serial
	private static final long serialVersionUID = 1L;

	@PrePersist
	protected void onCreate() {
		this.uniqueId = UUID.randomUUID().toString();
		if (this.createdAt == null) {
			this.createdAt = LocalDateTime.now();
		}
		if (this.updatedAt == null) {
			this.updatedAt = LocalDateTime.now();
		}
		if (memberRole == null) {
			memberRole = MemberRole.ROLE_USER;
		}
		if (memberStatus == null) {
			memberStatus = MemberStatus.ACTIVE;
		}

	}

	@PreUpdate
	protected void onUpdate() {
		this.updatedAt = LocalDateTime.now();
	}
}
