---
layout: post
title: Spring Boot Security ����
author: �Ĵ���ũ
description: Spring Boot Security ����
tags: [spring,spring boot,spring boot security,csrf]
featuredImage: 
img: 
categories: spring boot
date: '2022-08-01'
extensions:
  preset: gfm

---

Spring Boot Security ����
======================

# 1. web.xml ������ �߰�
### - WEB-INF/web.xml
```xml
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://java.sun.com/xml/ns/javaee" xmlns:jsp="http://java.sun.com/xml/ns/javaee/jsp" xmlns:web="http://java.sun.com/xml/ns/javaee" xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd" id="WebApp_ID" version="2.5">
 <listener>
      <listener-class>org.springframework.security.web.session.HttpSessionEventPublisher</listener-class>
 </listener>
</web-app>
```

# 2. userVO ��ť��Ƽ VO ����
### - knlframework.site.service.UserVO.java
## 1. UserDetails ����
```java
public class UserVO extends ComDefaultVO implements UserDetails {
```

## 2. �������� ���� �� Override�� ���� �߰�
```java
        private Collection<? extends GrantedAuthority> authorities;
        /**
	 * �α��� ���� Ƚ��
	 */
	private int fail_cnt = 5;
	/**
	 * ���Ǹ��Ῡ��
	 */
	private boolean is_account_non_expired = true;
	/**
	 * �α�����迩��
	 */
	private boolean is_account_non_locked = true;
	/**
	 * ������������Ῡ��(�̻��)
	 */
	private boolean is_credentials_non_expired = true;
	/**
	 * Ȱ��ȭ����
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
	
	// ���� ���� �� �߿� !! ��������
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

# 3. ��ť��Ƽ ���� ���� �߰�
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
         .authorizeRequests() // �ش� �޼ҵ� �Ʒ��� �� ��ο� ���� ������ ������ �� �ִ�.
         	 .antMatchers("/admt/**").hasRole("ADMIN") // ��ȣ�� ������ ���� ������ ���ٰ���, ROLE_�� �پ ���� ��. ��, ���̺� ROLE_���Ѹ� ���� �����ؾ� ��.
             .antMatchers("/loginForm.do", "/resources/**", "/css/**", "/js/**", "/images/**", "/WEB-INF/**")
			 .permitAll() // �α��� ������ ������, resources���ϵ� ������
             .anyRequest().authenticated() //  �α��ε� ����ڰ� ��û�� ������ �� �ʿ��ϴ�  ���� ����ڰ� �������� �ʾҴٸ�, ������ ��ť��Ƽ ���ʹ� ��û�� ��Ƴ��� ����ڸ� �α��� �������� �����̷��� ���ش�.
             .and()
         .formLogin()
             .loginPage("/loginForm.do")
             .loginProcessingUrl("/login.do")
             .usernameParameter("user_id")
             .passwordParameter("user_pw")
             .defaultSuccessUrl("/admt/main.do")
//           .failureUrl("/loginForm.do") // ������ �������� �� �����ִ� ȭ�� url, �α��� form���� �Ķ���Ͱ� error=true�� ������. , failureHandler ������� ���ʿ�������.
             .successHandler(successHandler)
             .failureHandler(failureHandler)
             .permitAll()
             .and()
         .logout()
             .logoutRequestMatcher(new AntPathRequestMatcher("/logout.do"))
             .logoutSuccessUrl("/loginForm.do") // ���� �� �̵� ������
    		 .deleteCookies("JSESSIONID")
    		 .permitAll()
    		 .and()
		 .sessionManagement()     		// ���ǰ��� ��� �۵�
			.maximumSessions(1)             // �ִ� ��� ���� ���Ǽ�, -1:����
			.maxSessionsPreventsLogin(true) // ���÷α��� ���� , false:�������Ǹ�
			.expiredUrl("/expired.do");			// ������ ����� ��� �̵��� ������
//         .and()
//             .exceptionHandling() // ���� ó��
//             .accessDeniedPage("/error.do"); // ���� �� �̵��� ������

	
//		http.csrf().ignoringAntMatchers("/resources/**") // �ƹ����ص� �ȵ� .....
//			.ignoringAntMatchers("/css/**")
//			.ignoringAntMatchers("/js/**")
//			.ignoringAntMatchers("/images/**")
//			.ignoringAntMatchers("/WEB-INF/**")
//			.ignoringAntMatchers("/common/**")
//			.ignoringAntMatchers("/admt/**");
//		http.csrf().disable();
		http.headers().frameOptions().sameOrigin(); // ������Ʈ �� origin iframe csrf ���
	}
	
	/**
	 * ���� ���������ϱ� ���� ������
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
	
	// ���� ó���� ���� Handler
	@Bean
	public AuthenticationFailureHandler failureHandler() {
		log.info("[ BEAN ] : failureHandler");
		return new LoginAuthenticationFailureHandler("user_id", "user_pw" , "loginRedirectUrl" , "exceptionMsgName" , "/loginForm.do");
	}
	
	// ���� ó���� ���� Handler
	@Bean
	public AuthenticationSuccessHandler successHandler() {
		  log.info("[ BEAN ] : AuthenticationSuccessHandler");
		  // loginIdname, defaultUrl
	      return new LoginAuthenticationSuccessHandler("user_id", "/admt/main.do");
	}
}
```

# 4. LoginService ����
### - knlframework.def.service.impl.LoginServiceImpl.java
// TODO �� �� ��Ī �����ʿ�
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
 * �α���
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

# 5. ��ť��Ƽ �α��� �ڵ鷯 �߰�
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
 * ���� provider custom
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

		// pw������ ����.
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
 * �α��� ���� �ڵ鷯
 * 
 * @author Hoon
 *
 */
public class LoginAuthenticationFailureHandler implements AuthenticationFailureHandler {

	/** Log Info */
	protected Log log = LogFactory.getLog(this.getClass());

	@Resource(name = "commonDAO")
	private CommonDAO commonDAO;

	private String loginIdName; // �α��� id���� ������ input�±� name
	private String loginPasswordName; // �α��� pw���� ������ input�±� name
	private String loginRedirectUrl; // �α��� ������ redirect �� URL�� �����Ǿ� �ִ� input�±� name
	private String exceptionMsgName; // ���� �޽����� REQUEST�� ATTRIBUTE�� ������ �� ���
	private String defaultFailureUrl; // ȭ�鿡 ������ url(�α��� ȭ��)

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
			// ���������� Ȯ���Ͽ�, errormsg�������ش�.
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

		// ������ ������� �߰��� ����Ƚ�� ������Ű���ʰ�, true�� return�Ѵ�.
		boolean userUnLock = true;

		// ����Ƚ�� select
		UserVO loginVO = new UserVO();
		loginVO.setUser_id(loginId);
		loginVO = (UserVO) commonDAO.selectView(loginVO, "loginDAO.loginUserInfo");
		userUnLock = loginVO.isEnabled();

		// ������ Ȱ��ȭ �Ǿ��ִ� ��쿡�� ����Ƚ����, Enabled������ �����Ѵ�.
		// Enabled������ ����Ƚ���� 5�̻��� �� �ٲ��.
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
 * �α��� ���� �ڵ鷯
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

		// ����ȸ�� �ʱ�ȭ
		UserVO loginVO = new UserVO();
		loginVO.setUser_id(requestUserName);
		commonDAO.update(loginVO, "loginDAO.resetFailCnt");
		commonDAO.update(loginVO, "loginDAO.updateLogin");
		// �������� �����
		clearAuthenticationAttributes(request);
		// Redirect URL �۾�.
		resultRedirectStrategy(request, response, authentication);

	}

	// redirectUrl ���� �޼���
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

	// �����ִ� ���������� �ִٸ� �����ش�.
	protected void clearAuthenticationAttributes(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		if (session == null)
			return;
		session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
	}

}
```

# 6. Mybatis Mapper �߰�
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

	<!-- ��ȸ  -->
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
	<!-- //��ȸ -->
	
	<!-- ��ȸ  -->
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
	<!-- //��ȸ -->
	
	<!-- ������ �α��� ���� -->
	<update id="updateLogin" parameterType="userVO">
	<![CDATA[
		UPDATE T_USER SET LAST_LOGIN_DT = now() WHERE USER_ID = #{user_id}
	]]>
	</update>
	<!-- //������ �α��� ���� -->
	

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

# 7. ���� �޼��� ����
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
	 * �޼��� �ҽ��� �����Ѵ�.
	 */

	@Bean
	public ReloadableResourceBundleMessageSource messageSource() {

		ReloadableResourceBundleMessageSource source = new ReloadableResourceBundleMessageSource();

		source.setBasename("classpath:/egovframework/messages/message");

		// �⺻ ���ڵ��� �����Ѵ�.
		source.setDefaultEncoding("UTF-8");

		// ������Ƽ ������ ������ ������ �ð� ������ �����Ѵ�.
		source.setCacheSeconds(60);

		// ���� �޼����� ��� ���ܸ� �߻���Ű�� ��� �ڵ带 �⺻ �޼����� �Ѵ�.
		source.setUseCodeAsDefaultMessage(true);
		return source;

	}

	/**
	 * ����� ��� ������ ����� ������ �����۸� �����Ѵ�. ���⼭�� ���ǿ� �����ϴ� ����� ����Ѵ�.
	 */

	@Bean
	public SessionLocaleResolver localeResolver() {
		return new SessionLocaleResolver();
	}

}
```

# 8. ���� �޼��� ����(���� ���ø� �ش�)
### - egovframework/messages/message.properties
```properties
AbstractAccessDecisionManager.accessDenied = ������ �źεǾ����ϴ�.
AbstractLdapAuthenticationProvider.emptyPassword = ��й�ȣ�� ���� �ʽ��ϴ�.
AbstractSecurityInterceptor.authenticationNotFound = SecurityContext���� Authentication ��ü�� ã�� �� �����ϴ�.
AbstractUserDetailsAuthenticationProvider.badCredentials = ���̵� Ȥ�� ��й�ȣ�� ���� �ʽ��ϴ�.
AbstractUserDetailsAuthenticationProvider.credentialsExpired = �ڰ� ���� ��ȿ �Ⱓ�� ����Ǿ����ϴ�.
AbstractUserDetailsAuthenticationProvider.disabled = ��ȿ���� ���� ������Դϴ�.
AbstractUserDetailsAuthenticationProvider.expired = ����� ������ ��ȿ �Ⱓ�� ���� �Ǿ����ϴ�.
AbstractUserDetailsAuthenticationProvider.locked = ����� ������ ��� �ֽ��ϴ�.
AbstractUserDetailsAuthenticationProvider.onlySupports = UsernamePasswordAuthenticationToken�� �����մϴ�.
AccountStatusUserDetailsChecker.credentialsExpired = �ڰ� ���� ��ȿ �Ⱓ�� ����Ǿ����ϴ�.
AccountStatusUserDetailsChecker.disabled = ������ ��Ȱ��ȭ �����Դϴ�. �����ڿ��� �����ϼ���.
AccountStatusUserDetailsChecker.expired = ����� ������ ��ȿ �Ⱓ�� ���� �Ǿ����ϴ�.
AccountStatusUserDetailsChecker.locked = ����� ������ ��� �ֽ��ϴ�.
AclEntryAfterInvocationProvider.noPermission = domain object {1}�� ���� ������ Authentication {0}�� �����ϴ�.
AnonymousAuthenticationProvider.incorrectKey = ������ AnonymousAuthenticationToken���� �ʿ���ϴ� key�� �����ϴ�.
BindAuthenticator.badCredentials = �ڰ� ���� �����Ͽ����ϴ�.
BindAuthenticator.emptyPassword = ��й�ȣ �׸��� ��� �ֽ��ϴ�.
CasAuthenticationProvider.incorrectKey = ������ CasAuthenticationToken���� �ʿ�� �ϴ� key�� �����ϴ�.
CasAuthenticationProvider.noServiceTicket = ������ ���� CAS ���� Ƽ���� ������ �� �����ϴ�.
ConcurrentSessionControlAuthenticationStrategy.exceededAllowed = �ִ� ���� ��� �� {0}���� �ʰ��Ͽ����ϴ�.
DigestAuthenticationFilter.incorrectRealm = ���� realm �̸� {0}�� �ý��� realm �̸� {1}�� ��ġ���� �ʽ��ϴ�.
DigestAuthenticationFilter.incorrectResponse = ������ ��Ȯ���� �ʽ��ϴ�.
DigestAuthenticationFilter.missingAuth = 'auth' QOP(quality of protection)�� ���� digest ���� �ʼ� �׸��Դϴ�. ���� header ���� {0}�Դϴ�.
DigestAuthenticationFilter.missingMandatory = digest ���� �ʼ� �׸��Դϴ�. ���� header ���� {0}�Դϴ�.
DigestAuthenticationFilter.nonceCompromised = Nonce ��ū�� �ջ�Ǿ����ϴ�. ���� nonce ���� {0}�Դϴ�.
DigestAuthenticationFilter.nonceEncoding = Nonce ���� Base64�� ���ڵ� �Ǿ����� �ʽ��ϴ�. ���� nonce ���� {0}�Դϴ�.
DigestAuthenticationFilter.nonceExpired = Nonce�� ��ȿ �Ⱓ�� ����Ǿ��ų� �ð��� �ʰ��Ǿ����ϴ�.
DigestAuthenticationFilter.nonceNotNumeric = Nonce ��ū�� ù ���ڴ� ���ڷ� �����ؾ� �մϴ�. ���� nonce ���� {0}�Դϴ�.
DigestAuthenticationFilter.nonceNotTwoTokens = Nonce�� �� ���� ��ū�� ������ �մϴ�. ���� nonce ���� {0}�Դϴ�.
DigestAuthenticationFilter.usernameNotFound = [ {0} ]��(��) �������� �ʴ�  ID�Դϴ�.
JdbcDaoImpl.noAuthority = {0} ����ڴ� ������ �����ϴ�.
JdbcDaoImpl.notFound = {0} ����ڸ� ã�� �� �����ϴ�.
LdapAuthenticationProvider.badCredentials = �ڰ� ���� �����Ͽ����ϴ�.
LdapAuthenticationProvider.credentialsExpired = �ڰ� ���� ��ȿ �Ⱓ�� ����Ǿ����ϴ�.
LdapAuthenticationProvider.disabled = ��ȿ���� ���� ������Դϴ�.
LdapAuthenticationProvider.expired = ����� ������ ��ȿ �Ⱓ�� ���� �Ǿ����ϴ�.
LdapAuthenticationProvider.locked = ����� ������ ��� �ֽ��ϴ�.
LdapAuthenticationProvider.emptyUsername = ID�� ������ ������ �ʽ��ϴ�.
LdapAuthenticationProvider.onlySupports = UsernamePasswordAuthenticationToken�� �����մϴ�.
PasswordComparisonAuthenticator.badCredentials = �ڰ� ���� �����Ͽ����ϴ�.
PersistentTokenBasedRememberMeServices.cookieStolen = �α��� ���� ������ ���� ��ū�� ��ġ���� �ʽ��ϴ�. ������ ����� ��ū�� Ÿ�����κ��� Ż�� ������ �� �ֽ��ϴ�.
ProviderManager.providerNotFound = {0}�� ���� AuthenticationProvider�� ã�� �� �����ϴ�.
RememberMeAuthenticationProvider.incorrectKey = ������ RememberMeAuthenticationToken���� �ʿ�� �ϴ� key�� �����ϴ�.
RunAsImplAuthenticationProvider.incorrectKey = ������ RunAsUserToken���� �ʿ�� �ϴ� key�� �����ϴ�.
SubjectDnX509PrincipalExtractor.noMatching = subjectDN\: {0} ���� ��Ī�Ǵ� ������ �����ϴ�.
SwitchUserFilter.noCurrentUser = ��û�� ����ڸ� ã�� �� �����ϴ�.
SwitchUserFilter.noOriginalAuthentication = Authentication ��ü�� ������ ã�� �� �����ϴ�.

#���� �űԷ� �߰��� ��
AbstractUserDetailsAuthenticationProvider.InternalAuthentication = ���������� �߻��� �ý��� ������ ���� ���� ��û�� ó�� �� �������ϴ�.

```