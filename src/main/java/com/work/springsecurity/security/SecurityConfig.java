package com.work.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired DriverManagerDataSource dataSource;

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {

    auth.jdbcAuthentication().dataSource(dataSource)
      .authoritiesByUsernameQuery(" select mail, role from admin where mail = ? ")
      .usersByUsernameQuery(" select mail, pass, 1 from admin where mail = ? ");
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {

      http
        .httpBasic()
        .and()
        .authorizeRequests()
        .anyRequest()
       .authenticated()
        .antMatchers("/login").permitAll()//herkes ziyaret edebilir.
       .antMatchers("/admin/**").hasAnyAuthority("ADMIN")
       .antMatchers("/user/**").hasAnyAuthority("USER")
        .antMatchers("/product").hasAnyRole("ADMIN","USER")
       .and()
       .csrf()
       .disable();
  }

  @SuppressWarnings("deprecation")
  @Bean
  public static NoOpPasswordEncoder passwordEncoder() {
    return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
  }
}
