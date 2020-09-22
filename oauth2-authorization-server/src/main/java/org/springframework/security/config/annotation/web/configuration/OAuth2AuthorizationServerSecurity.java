/*
 * Copyright 2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.web.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * {@link WebSecurityConfigurerAdapter} providing default security configuration for OAuth 2.0 Authorization Server.
 *
 * @author Joe Grandja
 * @since 0.0.1
 */
@Order(Ordered.HIGHEST_PRECEDENCE)
public class OAuth2AuthorizationServerSecurity extends WebSecurityConfigurerAdapter {

	// @formatter:off
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
				new OAuth2AuthorizationServerConfigurer<>();

		http
			.requestMatcher(new OrRequestMatcher(authorizationServerConfigurer.getEndpointMatchers()))
			.authorizeRequests(authorizeRequests ->
				authorizeRequests
						.anyRequest().authenticated()
			)
			.formLogin(withDefaults())
			.csrf(csrf -> csrf.ignoringRequestMatchers(tokenEndpointMatcher(),tokenOptionsEndpointMatcher() ))
			.apply(authorizationServerConfigurer);
//		http.cors(withDefaults());
	}

//	@Override
//	public void configure(WebSecurity web) throws Exception {
//		web.ignoring()
//				.antMatchers(HttpMethod.OPTIONS);
//	}
	// @formatter:on

//	@Bean
//	CorsConfigurationSource corsConfigurationSource() {
//		CorsConfiguration configuration = new CorsConfiguration();
//		configuration.setAllowedOrigins(Arrays.asList("http://localhost:1024"));
//		configuration.setAllowedMethods(Arrays.asList("GET","POST"));
//		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//		source.registerCorsConfiguration("/**", configuration);
//		return source;
//	}

	private static RequestMatcher tokenEndpointMatcher() {
		return new AntPathRequestMatcher(
				OAuth2TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI,
				HttpMethod.POST.name());
	}

	private static RequestMatcher tokenOptionsEndpointMatcher() {
		return new AntPathRequestMatcher(
				OAuth2TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI,
				HttpMethod.OPTIONS.name());
	}
}
