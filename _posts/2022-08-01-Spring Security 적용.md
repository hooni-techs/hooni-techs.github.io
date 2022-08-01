---
layout: post
title: Spring Boot Security 적용
author: 후니테크
description: Spring Boot Security 적용
tags: [spring,spring boot,spring boot security,csrf]
featuredImage: 
img: 
categories: spring boot
date: '2022-08-01'
extensions:
  preset: gfm

---

Spring Boot Security 적용
======================

# 1. web.xml 리스너 추가
### - WEB-INF/web.xml
```xml
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://java.sun.com/xml/ns/javaee" xmlns:jsp="http://java.sun.com/xml/ns/javaee/jsp" xmlns:web="http://java.sun.com/xml/ns/javaee" xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd" id="WebApp_ID" version="2.5">
 <listener>
      <listener-class>org.springframework.security.web.session.HttpSessionEventPublisher</listener-class>
 </listener>
</web-app>
```

# 2. userVO 시큐리티 VO 구현
### - knlframework.site.service.UserVO.java
## 1. UserDetails 구현
```java
public class UserVO extends ComDefaultVO implements UserDetails {
```

## 2. 인증관련 변수 및 Override된 변수 추가
```java
        private Collection<? extends GrantedAuthority> authorities;
        /**
	 * 로그인 실패 횟수
	 */
	private int fail_cnt = 5;
	/**
	 * 세션만료여부
	 */
	private boolean is_account_non_expired = true;
	/**
	 * 로그인잠김여부
	 */
	private boolean is_account_non_locked = true;
	/**
	 * 사용자인증만료여부(미사용)
	 */
	private boolean is_credentials_non_expired = true;
	/**
	 * 활성화여부
	 */
	private boolean is_enabled = true;

        @Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	public void setAuthorities(Collection<? extends GrantedAuthority> authorities) {
		this.authorities = authorities;
	}

        public boolean isIs_account_non_expired() {
		return is_account_non_expired;
	}

	public void setIs_account_non_expired(boolean is_account_non_expired) {
		this.is_account_non_expired = is_account_non_expired;
	}

	public boolean isIs_account_non_locked() {
		return is_account_non_locked;
	}

	public void setIs_account_non_locked(boolean is_account_non_locked) {
		this.is_account_non_locked = is_account_non_locked;
	}

	public boolean isIs_credentials_non_expired() {
		return is_credentials_non_expired;
	}

	public void setIs_credentials_non_expired(boolean is_credentials_non_expired) {
		this.is_credentials_non_expired = is_credentials_non_expired;
	}

	public boolean isIs_enabled() {
		return is_enabled;
	}

	public void setIs_enabled(boolean is_enabled) {
		this.is_enabled = is_enabled;
	}

        @Override
	public String getPassword() {
		// TODO Auto-generated method stub
		return this.user_pw;
	}

	@Override
	public String getUsername() {
		// TODO Auto-generated method stub
		return this.user_id;
	}

	@Override
	public boolean isAccountNonExpired() {
		// TODO Auto-generated method stub
		return this.is_account_non_expired;
	}

	@Override
	public boolean isAccountNonLocked() {
		// TODO Auto-generated method stub
		return this.is_account_non_locked;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		// TODO Auto-generated method stub
		return this.is_credentials_non_expired;
	}

	@Override
	public boolean isEnabled() {
		// TODO Auto-generated method stub
		return this.is_enabled;
	}
	
	// 세션 제거 시 중요 !! 삭제금지
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof UserVO)) return false;
            UserVO that = (UserVO) o;
            return user_id.equals(that.user_id) &&
                    email.equals(that.email) &&
                    user_pw.equals(that.user_pw);
        }
    
        @Override
        public int hashCode() {
            return Objects.hash(user_id, email, user_pw);
        }
```

# 3. 시큐리티 설정 파일 추가
### - knlframework.WebSecurityConfig.java
```java
package knlframework;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import knlframework.com.def.service.impl.LoginAuthenticationFailureHandler;
import knlframework.com.def.service.impl.LoginAuthenticationSuccessHandler;

/**
 * Security
 * @author Hoon
 * @lastUpdate 2022.07.29
 * @version 1.0
 */
@EnableWebSecurity
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	
	/** Log Info */
	protected Log log = LogFactory.getLog(this.getClass());

	@Autowired
	private AuthenticationFailureHandler failureHandler;
	
	@Autowired
	private AuthenticationSuccessHandler successHandler;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		 http
         .authorizeRequests() // 해당 메소드 아래는 각 경로에 따른 권한을 지정할 수 있다.
         	 .antMatchers("/admt/**").hasRole("ADMIN") // 괄호의 권한을 가진 유저만 접근가능, ROLE_가 붙어서 적용 됨. 즉, 테이블에 ROLE_권한명 으로 저장해야 함.
             .antMatchers("/loginForm.do", "/resources/**", "/css/**", "/js/**", "/images/**", "/WEB-INF/**")
			 .permitAll() // 로그인 권한은 누구나, resources파일도 모든권한
             .anyRequest().authenticated() //  로그인된 사용자가 요청을 수행할 떄 필요하다  만약 사용자가 인증되지 않았다면, 스프링 시큐리티 필터는 요청을 잡아내고 사용자를 로그인 페이지로 리다이렉션 해준다.
             .and()
         .formLogin()
             .loginPage("/loginForm.do")
             .loginProcessingUrl("/login.do")
             .usernameParameter("user_id")
             .passwordParameter("user_pw")
             .defaultSuccessUrl("/admt/main.do")
//           .failureUrl("/loginForm.do") // 인증에 실패했을 때 보여주는 화면 url, 로그인 form으로 파라미터값 error=true로 보낸다. , failureHandler 사용으로 불필요해졌다.
             .successHandler(successHandler)
             .failureHandler(failureHandler)
             .permitAll()
             .and()
         .logout()
             .logoutRequestMatcher(new AntPathRequestMatcher("/logout.do"))
             .logoutSuccessUrl("/loginForm.do") // 성공 시 이동 페이지
    		 .deleteCookies("JSESSIONID")
    		 .permitAll()
    		 .and()
		 .sessionManagement()     		// 세션관리 기능 작동
			.maximumSessions(1)             // 최대 허용 가능 세션수, -1:무제
			.maxSessionsPreventsLogin(true) // 동시로그인 차단 , false:기존세션만
			.expiredUrl("/expired.do");			// 세션이 만료된 경우 이동할 페이지
//         .and()
//             .exceptionHandling() // 에러 처리
//             .accessDeniedPage("/error.do"); // 에러 시 이동할 페이지

	
//		http.csrf().ignoringAntMatchers("/resources/**") // 아무리해도 안됨 .....
//			.ignoringAntMatchers("/css/**")
//			.ignoringAntMatchers("/js/**")
//			.ignoringAntMatchers("/images/**")
//			.ignoringAntMatchers("/WEB-INF/**")
//			.ignoringAntMatchers("/common/**")
//			.ignoringAntMatchers("/admt/**");
//		http.csrf().disable();
		http.headers().frameOptions().sameOrigin(); // 프로젝트 내 origin iframe csrf 허용
	}
	
	/**
	 * 세션 동시접속하기 위한 리스너
	 * 
	 * @see https://stackoverflow.com/questions/37892563/spring-security-maxsession-doesnt-work
	 * @return
	 */
	@Bean
    public ServletListenerRegistrationBean<HttpSessionEventPublisher> httpSessionEventPublisher() {
        return new ServletListenerRegistrationBean<HttpSessionEventPublisher>(new HttpSessionEventPublisher());
    }
    
	@Bean
	public PasswordEncoder passwordEncoder() {
		log.info("[ BEAN ] : passwordEncoder");
	    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}
	
	// 실패 처리를 위한 Handler
	@Bean
	public AuthenticationFailureHandler failureHandler() {
		log.info("[ BEAN ] : failureHandler");
		return new LoginAuthenticationFailureHandler("user_id", "user_pw" , "loginRedirectUrl" , "exceptionMsgName" , "/loginForm.do");
	}
	
	// 성공 처리를 위한 Handler
	@Bean
	public AuthenticationSuccessHandler successHandler() {
		  log.info("[ BEAN ] : AuthenticationSuccessHandler");
		  // loginIdname, defaultUrl
	      return new LoginAuthenticationSuccessHandler("user_id", "/admt/main.do");
	}
}
```

# 4. LoginService 변경
### - knlframework.def.service.impl.LoginServiceImpl.java
// TODO 추 후 명칭 수정필요
```java
package knlframework.com.def.service.impl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.annotation.Resource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.egovframe.rte.fdl.cmmn.EgovAbstractServiceImpl;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import knlframework.com.site.service.UserVO;

/**
 * 로그인
 * 
 * @author Administrator
 *
 */
@Service("loginService")
public class LoginServiceImpl extends EgovAbstractServiceImpl implements UserDetailsService {

	/** Log Info */
	protected Log log = LogFactory.getLog(this.getClass());

	@Resource(name = "commonDAO")
	private CommonDAO commonDAO;

	@Override
	public UserDetails loadUserByUsername(String user_id) throws UsernameNotFoundException {
		UserVO loginVO = null;
		UserVO searchVO = new UserVO();
		searchVO.setUser_id(user_id);
		loginVO = (UserVO) commonDAO.selectView(searchVO, "loginDAO.loginUserInfo");
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		if (loginVO == null) {
			log.debug("fail.user.no_exist");
			throw new UsernameNotFoundException("fail.user.no_exist");
		}
		
		for(int i=0;i<loginVO.getMem_cd().split(",").length; i++) {
			String auth = loginVO.getMem_cd().split(",")[i];
			authorities.add(new SimpleGrantedAuthority(auth));
		}
		loginVO.setAuthorities(authorities);
		return loginVO;
	}
}
```

# 5. 시큐리티 로그인 핸들러 추가
### - knlframework.LoginAuthenticationProvider.java
```java
package knlframework;

import javax.annotation.Resource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import knlframework.com.def.service.impl.LoginServiceImpl;
import knlframework.com.site.service.UserVO;

/**
 * 인증 provider custom
 * 
 * @author hoon
 *
 */
@Component
public class LoginAuthenticationProvider implements AuthenticationProvider {

	/** Log Info */
	protected Log log = LogFactory.getLog(this.getClass());

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Resource(name = "loginService")
	private LoginServiceImpl loginService;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		log.info("### authenticate ### ");

		String username = (String) authentication.getPrincipal();
		String password = (String) authentication.getCredentials();

		UserVO loginVO = (UserVO) loginService.loadUserByUsername(username);

		// pw같은지 검증.
		if (!passwordEncoder.matches(password, loginVO.getPassword())) {
			throw new BadCredentialsException(username);
		} else if (!loginVO.isEnabled()) {
			throw new DisabledException(username);
		} else if (!loginVO.isAccountNonExpired()) {
			throw new AccountExpiredException(username);
		} else if (!loginVO.isAccountNonLocked()) {
			throw new LockedException(username);
		} else if (!loginVO.isCredentialsNonExpired()) {
			throw new CredentialsExpiredException(username);
		}

		return new UsernamePasswordAuthenticationToken(loginVO, loginVO, loginVO.getAuthorities());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
	}
}
```

### - knlframework.def.service.impl.LoginAuthenticationFailureHandler.java
```java
package knlframework.com.def.service.impl;

import java.io.IOException;
import java.util.Locale;

import javax.annotation.Resource;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import knlframework.com.site.service.UserVO;

/**
 * 로그인 실패 핸들러
 * 
 * @author Hoon
 *
 */
public class LoginAuthenticationFailureHandler implements AuthenticationFailureHandler {

	/** Log Info */
	protected Log log = LogFactory.getLog(this.getClass());

	@Resource(name = "commonDAO")
	private CommonDAO commonDAO;

	private String loginIdName; // 로그인 id값이 들어오는 input태그 name
	private String loginPasswordName; // 로그인 pw값이 들어오는 input태그 name
	private String loginRedirectUrl; // 로그인 성공시 redirect 할 URL이 지정되어 있는 input태그 name
	private String exceptionMsgName; // 예외 메시지를 REQUEST의 ATTRIBUTE에 저장할 때 사용
	private String defaultFailureUrl; // 화면에 보여줄 url(로그인 화면)

	@Autowired
	MessageSource messageSource;

	public LoginAuthenticationFailureHandler(String loginIdName, String loginPasswordName, String loginRedirectUrl,
			String exceptionMsgName, String defaultFailureUrl) {
		this.loginIdName = loginIdName;
		this.loginPasswordName = loginPasswordName;
		this.loginRedirectUrl = loginRedirectUrl;
		this.exceptionMsgName = exceptionMsgName;
		this.defaultFailureUrl = defaultFailureUrl;
	}

	public String getLoginIdName() {
		return loginIdName;
	}

	public void setLoginIdName(String loginIdName) {
		this.loginIdName = loginIdName;
	}

	public String getLoginPasswordName() {
		return loginPasswordName;
	}

	public void setLoginPasswordName(String loginPasswordName) {
		this.loginPasswordName = loginPasswordName;
	}

	public String getLoginRedirectUrl() {
		return loginRedirectUrl;
	}

	public void setLoginRedirectUrl(String loginRedirectUrl) {
		this.loginRedirectUrl = loginRedirectUrl;
	}

	public String getExceptionMsgName() {
		return exceptionMsgName;
	}

	public void setExceptionMsgName(String exceptionMsgName) {
		this.exceptionMsgName = exceptionMsgName;
	}

	public String getDefaultFailureUrl() {
		return defaultFailureUrl;
	}

	public void setDefaultFailureUrl(String defaultFailureUrl) {
		this.defaultFailureUrl = defaultFailureUrl;
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {

		log.info("######### onAuthenticationFailure #########");

		String loginId = request.getParameter(loginIdName);
		String loginPw = request.getParameter(loginPasswordName);
		String loginRedirect = request.getParameter(loginRedirectUrl);
		String errormsg = exception.getMessage();

		if (exception instanceof BadCredentialsException) {
			// 잠긴계정인지 확인하여, errormsg변경해준다.
			boolean userUnLock = true;
			userUnLock = failCnt(loginId);
			if (!userUnLock) {
				errormsg = messageSource.getMessage("AccountStatusUserDetailsChecker.disabled", null, Locale.KOREA);
			} else {
				errormsg = messageSource.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", null, Locale.KOREA);
			}
		} else if (exception instanceof InternalAuthenticationServiceException) {
			errormsg = messageSource.getMessage("AbstractUserDetailsAuthenticationProvider.InternalAuthentication", null, Locale.KOREA);
		} else if (exception instanceof DisabledException) {
			errormsg = messageSource.getMessage("AccountStatusUserDetailsChecker.disabled", null, Locale.KOREA);
		} else if (exception instanceof CredentialsExpiredException) {
			errormsg = messageSource.getMessage("AccountStatusUserDetailsChecker.expired", null, Locale.KOREA);
		} else if (exception instanceof UsernameNotFoundException) {
			Object[] args = new String[] { loginId };
			errormsg = messageSource.getMessage("DigestAuthenticationFilter.usernameNotFound", args, Locale.KOREA);
		} else if (exception instanceof AccountExpiredException) {
			errormsg = messageSource.getMessage("AbstractUserDetailsAuthenticationProvider.expired", null, Locale.KOREA);
		} else if (exception instanceof LockedException) {
			errormsg = messageSource.getMessage("AbstractUserDetailsAuthenticationProvider.locked", null, Locale.KOREA);
		}

		request.setAttribute(loginIdName, loginId);
		request.setAttribute(loginPasswordName, loginPw);
		request.setAttribute(loginRedirectUrl, loginRedirect);
		request.setAttribute(exceptionMsgName, errormsg);

		log.info(" exception.getMessage() : " + exception.getMessage());

		request.getRequestDispatcher(defaultFailureUrl).forward(request, response);
	}

	private boolean failCnt(String loginId) {

		// 계정이 잠겼으면 추가로 실패횟수 증가시키지않고, true를 return한다.
		boolean userUnLock = true;

		// 실패횟수 select
		UserVO loginVO = new UserVO();
		loginVO.setUser_id(loginId);
		loginVO = (UserVO) commonDAO.selectView(loginVO, "loginDAO.loginUserInfo");
		userUnLock = loginVO.isEnabled();

		// 계정이 활성화 되어있는 경우에만 실패횟수와, Enabled설정을 변경한다.
		// Enabled설정은 실패횟수가 5이상일 때 바뀐다.
		if (userUnLock) {
			if (loginVO.getFail_cnt() < 5) {
				commonDAO.update(loginVO, "loginDAO.updateFailCnt");
			} else {
				commonDAO.update(loginVO, "loginDAO.changeEnabled");
			}
		}
		return userUnLock;
	}
}
```
### - knlframework.def.service.impl.LoginAuthenticationSuccessHandler.java
```java
package knlframework.com.def.service.impl;

import java.io.IOException;

import javax.annotation.Resource;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import knlframework.com.site.service.UserVO;

/**
 * 로그인 성공 핸들러
 * 
 * @author Hoon
 *
 */
public class LoginAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	/** Log Info */
	protected Log log = LogFactory.getLog(this.getClass());

	@Resource(name = "commonDAO")
	private CommonDAO commonDAO;

	private String user_id;
	private String defaultUrl;

	private RequestCache requestCache = new HttpSessionRequestCache();
	private RedirectStrategy redirectStragtegy = new DefaultRedirectStrategy();

	public String getDefaultUrl() {
		return defaultUrl;
	}

	public String getUsername() {
		return user_id;
	}

	public void setUsername(String user_id) {
		this.user_id = user_id;
	}

	public void setDefaultUrl(String defaultUrl) {
		this.defaultUrl = defaultUrl;
	}

	// Constructor
	public LoginAuthenticationSuccessHandler(String user_id, String defaultUrl) {
		this.user_id = user_id;
		this.defaultUrl = defaultUrl;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {

		String requestUserName = request.getParameter(user_id);

		// 실패회수 초기화
		UserVO loginVO = new UserVO();
		loginVO.setUser_id(requestUserName);
		commonDAO.update(loginVO, "loginDAO.resetFailCnt");
		commonDAO.update(loginVO, "loginDAO.updateLogin");
		// 에러세션 지우기
		clearAuthenticationAttributes(request);
		// Redirect URL 작업.
		resultRedirectStrategy(request, response, authentication);

	}

	// redirectUrl 지정 메서드
	protected void resultRedirectStrategy(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {

		SavedRequest savedRequest = requestCache.getRequest(request, response);

		if (savedRequest != null) {
			String targetUrl = savedRequest.getRedirectUrl();
			log.info("savedRequest.getRedirectUrl : " + targetUrl);
			redirectStragtegy.sendRedirect(request, response, targetUrl);
		} else {
			log.info("savedRequest.getRedirectUrl : " + defaultUrl);
			redirectStragtegy.sendRedirect(request, response, defaultUrl);
		}
	}

	// 남아있는 에러세션이 있다면 지워준다.
	protected void clearAuthenticationAttributes(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		if (session == null)
			return;
		session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
	}

}
```

# 6. Mybatis Mapper 추가
### - egovframework/mybatis/datasource1/def/Login_SQL_Mysql.xml
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper   PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">

<mapper namespace="loginDAO">

	<sql id="column">
	<![CDATA[
		USER_ID DB_KEY
		,USER_ID
		,MEM_CD
		,USER_NM
		,TEL
		,PHONE
		,EMAIL
		,POST
		,ADDR
		,ADDR_DTL
		,LAST_LOGIN_DT
		,PURPOSE
		,STATUS_CD
		,PW_EXPIRE_DT
		,LAST_UPD_DT
		,PW_EXPIRE
		,PROFILE_TCD
		,ACC_IP1
		,ACC_IP2
		,USE_YN
		,INS_ID
		,UPD_ID
		,INS_DT
		,UPD_DT
		,INS_IP
		,UPD_IP
		,SALT
		,IS_ACCOUNT_NON_EXPIRED
		,IS_ACCOUNT_NON_LOCKED
		,IS_CREDENTIALS_NON_EXPIRED
		,IS_ENABLED
		,FAIL_CNT
	]]>
	</sql>

	<!-- 조회  -->
	<select id="loginUserInfo" parameterType="userVO" resultType="userVO" flushCache="true">
		<![CDATA[
			SELECT
		]]><include refid="column" /><![CDATA[
			,USER_PW
			FROM T_USER
			WHERE 1=1
				AND USER_ID = #{user_id}
		]]>
	</select>	
	<!-- //조회 -->
	
	<!-- 조회  -->
	<select id="loginUser" parameterType="userVO" resultType="userVO" flushCache="true">
		<![CDATA[
			SELECT
		]]><include refid="column" /><![CDATA[
			FROM T_USER
			WHERE 1=1
				AND USER_ID = #{user_id}
				AND USER_PW = #{user_pw}
		]]>
	</select>	
	<!-- //조회 -->
	
	<!-- 마지막 로그인 갱신 -->
	<update id="updateLogin" parameterType="userVO">
	<![CDATA[
		UPDATE T_USER SET LAST_LOGIN_DT = now() WHERE USER_ID = #{user_id}
	]]>
	</update>
	<!-- //마지막 로그인 갱신 -->
	

	<update id="updateFailCnt" parameterType="userVO">
	<![CDATA[
		UPDATE T_USER SET FAIL_CNT = coalesce(FAIL_CNT, 0)+1 WHERE USER_ID = #{user_id}
	]]>
	</update>
	
	<update id="resetFailCnt" parameterType="String" >
	<![CDATA[
		UPDATE T_USER SET FAIL_CNT = 0
		WHERE USER_ID = #{user_id}
	]]>
	</update>
	
	<select id="selectFailCnt"  parameterType="userVO" resultType="userVO">
	<![CDATA[
		SELECT fail_cnt, is_enabled FROM T_USER
		WHERE USER_ID = #{user_id}
	]]>
	</select>
	
	<update id="changeEnabled" parameterType="string">
	<![CDATA[
		UPDATE T_USER 
		SET IS_ENABLED = (CASE IS_ENABLED WHEN CAST(1 as BOOLEAN) THEN CAST(0 as BOOLEAN) ELSE CAST(0 as BOOLEAN) END),
		FAIL_CNT = (CASE IS_ENABLED WHEN CAST(0 as BOOLEAN) THEN 0 ELSE FAIL_CNT END)
		WHERE USER_ID = #{user_id}
	]]>
	</update>

	
</mapper>            
```

# 7. 공통 메세지 설정
### - knlframework.WebContextMessage.java
```java
package knlframework;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ReloadableResourceBundleMessageSource;
import org.springframework.web.servlet.i18n.SessionLocaleResolver;

@Configuration
public class WebContextMessage {
	/**
	 * 메세지 소스를 생성한다.
	 */

	@Bean
	public ReloadableResourceBundleMessageSource messageSource() {

		ReloadableResourceBundleMessageSource source = new ReloadableResourceBundleMessageSource();

		source.setBasename("classpath:/egovframework/messages/message");

		// 기본 인코딩을 지정한다.
		source.setDefaultEncoding("UTF-8");

		// 프로퍼티 파일의 변경을 감지할 시간 간격을 지정한다.
		source.setCacheSeconds(60);

		// 없는 메세지일 경우 예외를 발생시키는 대신 코드를 기본 메세지로 한다.
		source.setUseCodeAsDefaultMessage(true);
		return source;

	}

	/**
	 * 변경된 언어 정보를 기억할 로케일 리졸퍼를 생성한다. 여기서는 세션에 저장하는 방식을 사용한다.
	 */

	@Bean
	public SessionLocaleResolver localeResolver() {
		return new SessionLocaleResolver();
	}

}
```

# 8. 공통 메세지 정의(인증 관련만 해당)
### - egovframework/messages/message.properties
```properties
AbstractAccessDecisionManager.accessDenied = 접근이 거부되었습니다.
AbstractLdapAuthenticationProvider.emptyPassword = 비밀번호가 맞지 않습니다.
AbstractSecurityInterceptor.authenticationNotFound = SecurityContext에서 Authentication 객체를 찾을 수 없습니다.
AbstractUserDetailsAuthenticationProvider.badCredentials = 아이디 혹은 비밀번호가 맞지 않습니다.
AbstractUserDetailsAuthenticationProvider.credentialsExpired = 자격 증명 유효 기간이 만료되었습니다.
AbstractUserDetailsAuthenticationProvider.disabled = 유효하지 않은 사용자입니다.
AbstractUserDetailsAuthenticationProvider.expired = 사용자 계정의 유효 기간이 만료 되었습니다.
AbstractUserDetailsAuthenticationProvider.locked = 사용자 계정이 잠겨 있습니다.
AbstractUserDetailsAuthenticationProvider.onlySupports = UsernamePasswordAuthenticationToken만 지원합니다.
AccountStatusUserDetailsChecker.credentialsExpired = 자격 증명 유효 기간이 만료되었습니다.
AccountStatusUserDetailsChecker.disabled = 계정이 비활성화 상태입니다. 관리자에게 문의하세요.
AccountStatusUserDetailsChecker.expired = 사용자 계정의 유효 기간이 만료 되었습니다.
AccountStatusUserDetailsChecker.locked = 사용자 계정이 잠겨 있습니다.
AclEntryAfterInvocationProvider.noPermission = domain object {1}에 대한 권한이 Authentication {0}에 없습니다.
AnonymousAuthenticationProvider.incorrectKey = 제공된 AnonymousAuthenticationToken에는 필요로하는 key가 없습니다.
BindAuthenticator.badCredentials = 자격 증명에 실패하였습니다.
BindAuthenticator.emptyPassword = 비밀번호 항목이 비어 있습니다.
CasAuthenticationProvider.incorrectKey = 제공된 CasAuthenticationToken에는 필요로 하는 key가 없습니다.
CasAuthenticationProvider.noServiceTicket = 검증을 위한 CAS 서비스 티켓을 제공할 수 없습니다.
ConcurrentSessionControlAuthenticationStrategy.exceededAllowed = 최대 세션 허용 수 {0}개를 초과하였습니다.
DigestAuthenticationFilter.incorrectRealm = 응답 realm 이름 {0}과 시스템 realm 이름 {1}이 일치하지 않습니다.
DigestAuthenticationFilter.incorrectResponse = 응답이 정확하지 않습니다.
DigestAuthenticationFilter.missingAuth = 'auth' QOP(quality of protection)를 위한 digest 값은 필수 항목입니다. 현재 header 값은 {0}입니다.
DigestAuthenticationFilter.missingMandatory = digest 값은 필수 항목입니다. 현재 header 값은 {0}입니다.
DigestAuthenticationFilter.nonceCompromised = Nonce 토큰이 손상되었습니다. 현재 nonce 값은 {0}입니다.
DigestAuthenticationFilter.nonceEncoding = Nonce 값이 Base64로 인코딩 되어있지 않습니다. 현재 nonce 값은 {0}입니다.
DigestAuthenticationFilter.nonceExpired = Nonce의 유효 기간이 만료되었거나 시간이 초과되었습니다.
DigestAuthenticationFilter.nonceNotNumeric = Nonce 토큰의 첫 글자는 숫자로 시작해야 합니다. 현재 nonce 값은 {0}입니다.
DigestAuthenticationFilter.nonceNotTwoTokens = Nonce는 두 개의 토큰을 만들어야 합니다. 현재 nonce 값은 {0}입니다.
DigestAuthenticationFilter.usernameNotFound = [ {0} ]은(는) 존재하지 않는  ID입니다.
JdbcDaoImpl.noAuthority = {0} 사용자는 권한이 없습니다.
JdbcDaoImpl.notFound = {0} 사용자를 찾을 수 없습니다.
LdapAuthenticationProvider.badCredentials = 자격 증명에 실패하였습니다.
LdapAuthenticationProvider.credentialsExpired = 자격 증명 유효 기간이 만료되었습니다.
LdapAuthenticationProvider.disabled = 유효하지 않은 사용자입니다.
LdapAuthenticationProvider.expired = 사용자 계정의 유효 기간이 만료 되었습니다.
LdapAuthenticationProvider.locked = 사용자 계정이 잠겨 있습니다.
LdapAuthenticationProvider.emptyUsername = ID에 공백은 허용되지 않습니다.
LdapAuthenticationProvider.onlySupports = UsernamePasswordAuthenticationToken만 지원합니다.
PasswordComparisonAuthenticator.badCredentials = 자격 증명에 실패하였습니다.
PersistentTokenBasedRememberMeServices.cookieStolen = 로그인 상태 유지를 위한 토큰이 일치하지 않습니다. 이전에 사용한 토큰이 타인으로부터 탈취 당했을 수 있습니다.
ProviderManager.providerNotFound = {0}을 위한 AuthenticationProvider를 찾을 수 없습니다.
RememberMeAuthenticationProvider.incorrectKey = 제공된 RememberMeAuthenticationToken에는 필요로 하는 key가 없습니다.
RunAsImplAuthenticationProvider.incorrectKey = 제공된 RunAsUserToken에는 필요로 하는 key가 없습니다.
SubjectDnX509PrincipalExtractor.noMatching = subjectDN\: {0} 내에 매칭되는 패턴이 없습니다.
SwitchUserFilter.noCurrentUser = 요청한 사용자를 찾을 수 없습니다.
SwitchUserFilter.noOriginalAuthentication = Authentication 객체의 원본을 찾을 수 없습니다.

#내가 신규로 추가한 것
AbstractUserDetailsAuthenticationProvider.InternalAuthentication = 내부적으로 발생한 시스템 문제로 인해 인증 요청을 처리 할 수없습니다.

```