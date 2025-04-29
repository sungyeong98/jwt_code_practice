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

/**
 * OAuth2 로그인 성공 시 호출되는 핸들러 클래스입니다.
 * <p>
 * 이 클래스는 Spring Security의 OAuth2 인증 과정에서 사용자가 성공적으로 인증된 후
 * 호출되는 핸들러로, 소셜 로그인 성공 후 처리 로직을 담당합니다.
 * 주요 기능으로는 사용자 정보 추출, 기존 회원 확인, JWT 토큰 발급, 응답 처리 등이 있습니다.
 * </p>
 * <p>
 * 주요 기능:
 * <ul>
 *   <li>OAuth2 인증 결과에서 사용자 정보 추출</li>
 *   <li>소셜 로그인 제공자(Google, Kakao 등) 식별</li>
 *   <li>제공자별 사용자 정보 변환 및 표준화</li>
 *   <li>이메일을 기반으로 기존 회원 여부 확인</li>
 *   <li>기존 회원인 경우 JWT 토큰 발급</li>
 *   <li>신규 회원인 경우 추가 회원가입 절차 안내 (현재는 TODO 상태)</li>
 *   <li>인증 성공/실패에 따른 적절한 응답 생성</li>
 *   <li>프론트엔드 페이지로 리다이렉트</li>
 * </ul>
 * </p>
 * <p>
 * 이 핸들러는 다음 컴포넌트들과 협력하여 동작합니다:
 * <ul>
 *   <li>{@link JwtTokenProvider}: 인증 성공 시 JWT 토큰 생성 및 쿠키 설정</li>
 *   <li>{@link MemberRepository}: 이메일을 기반으로 기존 회원 조회</li>
 *   <li>{@link OAuth2UserInfoFactory}: 소셜 로그인 제공자별 사용자 정보 추출</li>
 *   <li>{@link ObjectMapper}: JSON 응답 생성</li>
 * </ul>
 * </p>
 * <p>
 * 인증 흐름:
 * <ol>
 *   <li>사용자가 소셜 로그인(Google, Kakao 등) 버튼 클릭</li>
 *   <li>소셜 로그인 제공자의 인증 페이지로 리다이렉트</li>
 *   <li>사용자가 소셜 로그인 제공자에서 인증 완료</li>
 *   <li>제공자가 설정된 리다이렉트 URI로 인증 코드와 함께 리다이렉트</li>
 *   <li>Spring Security의 OAuth2 클라이언트가 인증 코드로 액세스 토큰 요청</li>
 *   <li>액세스 토큰으로 사용자 정보 요청</li>
 *   <li>인증 성공 시 이 핸들러의 {@link #onAuthenticationSuccess} 메소드 호출</li>
 *   <li>사용자 정보 처리 및 JWT 토큰 발급</li>
 *   <li>프론트엔드 페이지로 리다이렉트</li>
 * </ol>
 * </p>
 *
 * @author sungyeong98
 * @see AuthenticationSuccessHandler
 * @see JwtTokenProvider
 * @see OAuth2UserInfoFactory
 * @see com.jwt_code_practice.global.security.oauth.service.CustomOAuth2UserService
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {
	private final JwtTokenProvider jwtTokenProvider;
	private final ObjectMapper objectMapper;
	private final MemberRepository memberRepository;

	@Value("${FRONTEND_URL}")
	private String frontEndUrl;

	/**
	 * OAuth2 인증 성공 시 호출되는 메소드입니다.
	 * <p>
	 * 이 메소드는 Spring Security의 OAuth2 인증 과정에서 사용자가 성공적으로 인증된 후
	 * 자동으로 호출됩니다. 소셜 로그인 제공자로부터 받은 사용자 정보를 처리하고,
	 * 기존 회원 여부에 따라 적절한 후속 처리를 수행합니다.
	 * </p>
	 * <p>
	 * 처리 과정:
	 * <ol>
	 *   <li>OAuth2User 객체에서 사용자 정보 추출</li>
	 *   <li>소셜 로그인 제공자(registrationId) 식별</li>
	 *   <li>OAuth2UserInfoFactory를 통해 제공자별 사용자 정보 추출</li>
	 *   <li>사용자 이메일 추출</li>
	 *   <li>이메일을 기반으로 기존 회원 조회</li>
	 *   <li>기존 회원인 경우:
	 *     <ul>
	 *       <li>JWT 토큰 생성 및 쿠키 설정</li>
	 *       <li>성공 응답 생성</li>
	 *     </ul>
	 *   </li>
	 *   <li>신규 회원인 경우:
	 *     <ul>
	 *       <li>현재는 로그만 기록 (TODO: 추가 회원가입 절차 구현 예정)</li>
	 *     </ul>
	 *   </li>
	 *   <li>프론트엔드 URL로 리다이렉트</li>
	 * </ol>
	 * </p>
	 * <p>
	 * 예외 처리:
	 * <ul>
	 *   <li>처리 과정에서 예외 발생 시 로그 기록</li>
	 *   <li>에러 응답 생성</li>
	 * </ul>
	 * </p>
	 * <p>
	 * 이 메소드는 {@link AuthenticationSuccessHandler} 인터페이스의 구현으로,
	 * Spring Security 설정에서 다음과 같이 등록됩니다:
	 * <pre>
	 * http.oauth2Login()
	 *     .successHandler(oAuth2LoginSuccessHandler);
	 * </pre>
	 * </p>
	 *
	 * @param request 현재 HTTP 요청
	 * @param response 현재 HTTP 응답
	 * @param authentication 인증 성공 결과를 나타내는 Authentication 객체
	 * @throws IOException 응답 작성 또는 리다이렉트 중 I/O 오류 발생 시
	 * @see AuthenticationSuccessHandler#onAuthenticationSuccess
	 * @see OAuth2UserInfoFactory
	 * @see JwtTokenProvider#saveToken
	 */
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

	/**
	 * 인증 성공 시 JSON 응답을 생성합니다.
	 * <p>
	 * 이 메소드는 소셜 로그인이 성공적으로 처리되었을 때 클라이언트에게
	 * 성공 메시지를 JSON 형식으로 반환합니다. 주로 {@link #onAuthenticationSuccess} 메소드에서
	 * 기존 회원으로 확인된 경우 호출됩니다.
	 * </p>
	 * <p>
	 * 응답 설정:
	 * <ul>
	 *   <li>Content-Type: application/json;charset=UTF-8</li>
	 *   <li>Status: 200 OK</li>
	 * </ul>
	 * </p>
	 * <p>
	 * 응답 본문 형식:
	 * <pre>
	 * {
	 *   "success": true,
	 *   "message": "소셜 로그인 성공!"
	 * }
	 * </pre>
	 * </p>
	 * <p>
	 * 이 메소드는 {@link ObjectMapper}를 사용하여 Java 맵 객체를 JSON 문자열로 변환하고,
	 * {@link HttpServletResponse#getWriter()}를 통해 응답 본문에 작성합니다.
	 * </p>
	 *
	 * @param response 응답 객체
	 * @throws IOException 응답 작성 중 I/O 오류 발생 시
	 * @see ObjectMapper#writeValueAsString
	 */
	private void successResponse(HttpServletResponse response) throws IOException {
		response.setContentType("application/json;charset=UTF-8");
		response.setStatus(HttpServletResponse.SC_OK);

		Map<String, Object> responseBody = new HashMap<>();
		responseBody.put("success", true);
		responseBody.put("message", "소셜 로그인 성공!");

		response.getWriter().write(objectMapper.writeValueAsString(responseBody));
	}

	/**
	 * 인증 실패 시 JSON 에러 응답을 생성합니다.
	 * <p>
	 * 이 메소드는 소셜 로그인 처리 중 예외가 발생했을 때 클라이언트에게
	 * 에러 메시지를 JSON 형식으로 반환합니다. 주로 {@link #onAuthenticationSuccess} 메소드에서
	 * 예외가 발생한 경우 호출됩니다.
	 * </p>
	 * <p>
	 * 응답 설정:
	 * <ul>
	 *   <li>Content-Type: application/json;charset=UTF-8</li>
	 *   <li>Status: 401 Unauthorized</li>
	 * </ul>
	 * </p>
	 * <p>
	 * 응답 본문 형식:
	 * <pre>
	 * {
	 *   "success": false,
	 *   "message": "소셜 로그인에 실패하였습니다.",
	 *   "error": "구체적인 에러 메시지"
	 * }
	 * </pre>
	 * </p>
	 * <p>
	 * 이 메소드는 {@link ObjectMapper}를 사용하여 Java 맵 객체를 JSON 문자열로 변환하고,
	 * {@link HttpServletResponse#getWriter()}를 통해 응답 본문에 작성합니다.
	 * </p>
	 *
	 * @param response 응답 객체
	 * @param errorMessage 에러 메시지
	 * @throws IOException 응답 작성 중 I/O 오류 발생 시
	 * @see ObjectMapper#writeValueAsString
	 */
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
