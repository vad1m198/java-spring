package com.simpleouath2.demooauth2;

import java.security.Principal;
import java.util.List;

import javax.servlet.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@EnableOAuth2Client
@RestController
public class Demooauth2Application extends WebSecurityConfigurerAdapter {

	public static void main(String[] args) {
		SpringApplication.run(Demooauth2Application.class, args);
	}
	
	@Autowired
	OAuth2ClientContext oauth2ClientContext;
	
	@Autowired
    private Force force;
	
	@RequestMapping("/user")
    public Principal user(Principal principal) {
      return principal;
    }

    @RequestMapping("/accounts")
    public List<Force.Account> accounts(OAuth2Authentication principal) {    	
        return force.accounts(principal);
    }
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
	    http
	      .antMatcher("/**")
	      .authorizeRequests()
	        .antMatchers("/", "/login**", "/webjars/**")
	        .permitAll()
	      .anyRequest()
	        .authenticated()
	        .and().logout().logoutSuccessUrl("/").permitAll()
	        .and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
	        .and().addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
	}
	
	private Filter ssoFilter() {
		  OAuth2ClientAuthenticationProcessingFilter sfFilter = new OAuth2ClientAuthenticationProcessingFilter("/login/sf");
		  OAuth2RestTemplate sfTemplate = new OAuth2RestTemplate(sf(), oauth2ClientContext);
		  sfFilter.setRestTemplate(sfTemplate);
		  UserInfoTokenServices tokenServices = new UserInfoTokenServices(sfResource().getUserInfoUri(), sf().getClientId());
		  tokenServices.setRestTemplate(sfTemplate);
		  sfFilter.setTokenServices(tokenServices);
		  return sfFilter;
	}
	
	@Bean
	@ConfigurationProperties("sf.client")
	public AuthorizationCodeResourceDetails sf() {
	    return new AuthorizationCodeResourceDetails();
	}
	  
	@Bean
	@ConfigurationProperties("sf.resource")
	public ResourceServerProperties sfResource() {
	    return new ResourceServerProperties();
	}
	
	@Bean
	public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
	  FilterRegistrationBean registration = new FilterRegistrationBean();
	  registration.setFilter(filter);
	  registration.setOrder(-100);
	  return registration;
	}
}
