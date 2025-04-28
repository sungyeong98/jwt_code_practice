package com.jwt_code_practice.global.security.oauth.handler;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jwt_code_practice.domain.member.entity.Member;
import com.jwt_code_practice.domain.member.repository.MemberRepository;
import com.jwt_code_practice.global.security.jwt.JwtTokenProvider;
import com.jwt_code_practice.global.security.oauth.model.OAuth2UserInfo;
import com.jwt_code_practice.global.security.oauth.service.OAuth2UserInfoFactory;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {
	private final JwtTokenProvider jwtTokenProvider;
	private final ObjectMapper objectMapper;
	private final MemberRepository memberRepository;

	@Value("${FRONTEND_URL}")
	private String frontEndUrl;

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,  Authentication authentication) throws
		IOException {
		log.info("소셜 로그인 처리 중...");

		try {
			OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
			String registrationId = ((OAuth2AuthenticationToken) authentication).getAuthorizedClientRegistrationId();

			log.debug("소셜 로그인 제공자 : {}", registrationId);

			OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(registrationId, oAuth2User.getAttributes());

			String email = userInfo.getEmail();

			log.debug("소셜 로그인 사용자 이메일 : {}", email);

			Optional<Member> member = memberRepository.findByEmail(email);

			if (member.isPresent()) {
				log.info("이미 가입된 사용자 로그인 : {}", email);
				jwtTokenProvider.saveToken(authentication, response);

				successResponse(response);
				log.info("소셜 로그인 성공!");
			} else {
				log.info("새로운 사용자 등록 필요 : {}", email);
				// TODO (이후에 소셜 로그인을 바로 처리하지 않고, 신규 유저의 경우에는 회원가입 절차를 거치도록 설계할 예정)
			}

			response.sendRedirect(frontEndUrl);
		} catch (Exception e) {
			log.error("소셜 로그인 처리 중 오류 발생...", e);
			errorResponse(response, e.getMessage());
		}
	}

	private void successResponse(HttpServletResponse response) throws IOException {
		response.setContentType("application/json;charset=UTF-8");
		response.setStatus(HttpServletResponse.SC_OK);

		Map<String, Object> responseBody = new HashMap<>();
		responseBody.put("success", true);
		responseBody.put("message", "소셜 로그인 성공!");

		response.getWriter().write(objectMapper.writeValueAsString(responseBody));
	}

	private void errorResponse(HttpServletResponse response, String errorMessage) throws IOException {
		response.setContentType("application/json;charset=UTF-8");
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

		Map<String, Object> responseBody = new HashMap<>();
		responseBody.put("success", false);
		responseBody.put("message", "소셜 로그인에 실패하였습니다.");
		responseBody.put("error", errorMessage);

		response.getWriter().write(objectMapper.writeValueAsString(responseBody));
	}
}
