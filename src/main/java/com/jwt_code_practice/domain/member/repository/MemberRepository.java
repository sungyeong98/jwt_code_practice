package com.jwt_code_practice.domain.member.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.jwt_code_practice.domain.member.entity.Member;

/**
 * 사용자 레포지터리 클래스
 * @author sungyeong98
 */
@Repository
public interface MemberRepository extends JpaRepository<Member, Long> {
}
