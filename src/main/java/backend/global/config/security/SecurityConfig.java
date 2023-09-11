package astarmize.global.config.security;

import java.io.IOException;
import java.util.Arrays;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.fasterxml.jackson.databind.ObjectMapper;

import astarmize.global.config.security.filter.JwtAuthenticationFilter;
import astarmize.global.config.security.filter.JwtTokenProvider;
import astarmize.global.error.ErrorResponse;
import astarmize.global.error.exception.ExceptionCode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	// private final AuthenticationManager authenticationManager;
	private final JwtTokenProvider jwtTokenProvider;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			// .httpBasic(Customizer.withDefaults())
			// .csrf(Customizer.withDefaults())
			.csrf().disable()
			.headers().frameOptions().disable()
			.and()
			.cors().configurationSource(corsConfigurationSource())
			.and()
			.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			.exceptionHandling()
			.authenticationEntryPoint(new CustomAuthenticationEntryPoint())
			.accessDeniedHandler(new CustomAccessDeniedHandler())
			.and()
			.authenticationManager(new CustomAuthenticationManager(jwtTokenProvider))
			.securityContext()
			.securityContextRepository(new CustomSecurityContextRepository(authenticationManagerBean()))
			.and()
			.addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class)
			.authorizeRequests()
			.antMatchers("/h2/**").permitAll()
			.and()
			// .authorizeRequests(authorizeRequests ->
			// 	authorizeRequests
			// 		.antMatchers("/login", "/h2/**").permitAll()
			// 		.anyRequest().authenticated()
			// )
			.addFilter(new JwtAuthenticationFilter(jwtTokenProvider));
	}

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList("*"));
		configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
		configuration.setAllowCredentials(true);
		configuration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type"));

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

	private static class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
		@Override
		public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
			Exception exception = (Exception)request.getAttribute("exception");
			ErrorResponse errorResponse = ErrorResponse.of(ExceptionCode.UNAUTHORIZED);

			response.setContentType("application/json;charset=UTF-8");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			response.getWriter().write(new ObjectMapper().writeValueAsString(errorResponse));

			logExceptionMessage(authException, exception);
		}

		private void logExceptionMessage(AuthenticationException authException, Exception exception) {
			String message = exception != null ? exception.getMessage() : authException.getMessage();
			log.error("Unauthorized error happened: {}", message);
		}
	}

	private static class CustomAccessDeniedHandler implements AccessDeniedHandler {
		@Override
		public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
			ErrorResponse errorResponse = ErrorResponse.of(ExceptionCode.HANDLE_ACCESS_DENIED);

			response.setContentType("application/json;charset=UTF-8");
			response.setStatus(HttpServletResponse.SC_FORBIDDEN);
			response.getWriter().write(new ObjectMapper().writeValueAsString(errorResponse));

			log.error("Forbidden error happened: {}", accessDeniedException.getMessage());
		}
	}

	@RequiredArgsConstructor
	public class CustomAuthenticationManager implements AuthenticationManager {

		private final JwtTokenProvider jwtTokenProvider;  // 여기에서 JwtTokenProvider는 토큰을 검증하고 처리하는 클래스입니다.

		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			String authToken = authentication.getCredentials().toString();
			if (jwtTokenProvider.validateToken(authToken)) {
				String userId = jwtTokenProvider.getUsername(authToken);
				Authentication auth = jwtTokenProvider.getAuthentication(authToken);  // 토큰에서 Authentication 객체를 가져옵니다.
				return auth;
			} else {
				throw new BadCredentialsException("Invalid token");
			}
		}
	}

	@RequiredArgsConstructor
	public class CustomSecurityContextRepository implements SecurityContextRepository {

		private final AuthenticationManager authenticationManager;

		@Override
		public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
			HttpServletRequest request = requestResponseHolder.getRequest();
			String authHeader = request.getHeader("Authorization");

			if (authHeader != null && authHeader.startsWith("Bearer ")) {
				String authToken = authHeader.substring(7);
				Authentication auth = new UsernamePasswordAuthenticationToken(authToken, authToken);
				Authentication authenticatedAuth = authenticationManager.authenticate(auth);
				SecurityContext securityContext = new SecurityContextImpl(authenticatedAuth);
				return securityContext;
			}

			return SecurityContextHolder.createEmptyContext();
		}

		@Override
		public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
			// 보안 컨텍스트를 저장하는 로직. 일반적으로 JWT 사용 시 사용하지 않음
		}

		@Override
		public boolean containsContext(HttpServletRequest request) {
			String authHeader = request.getHeader("Authorization");
			return authHeader != null && authHeader.startsWith("Bearer ");
		}
	}
}
