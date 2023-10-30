package com.example.securityproject.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    //Configuration 1
    /* @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception{
        return httpSecurity
                .csrf().disable() //Cross-Site Request Forgery, que no puedan interceptar formularios enviados del navegador al servidor. Lo deshabilito porque no va a haber forms
                .authorizeHttpRequests()
                    .requestMatchers("v1/index2").permitAll()
                    .anyRequest().authenticated()
                .and()
                .formLogin().permitAll()
                .and()
                .build();
    } */

    //Configuration 2
   /* @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception{
        return httpSecurity
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/v1/index2").permitAll();
                    auth.anyRequest().authenticated();
                })
                .formLogin()
                    .successHandler(successHandler()) //Url a donde se redirige al loguearse correctamente
                    .permitAll()
                .and()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                        //ALWAYS: Crea una sesion siempre y cuando no haya una, sino la reutiliza
                        //IF_REQUIRED: Solo si no existe la crea y evalua si en serio es necesario creala
                        //NEVER: No crea sesion pero si hay una la va a utilizar
                        //STATELESS: No crea sesion ni trabaja con datos de sesion
                    .invalidSessionUrl("/login")
                    .maximumSessions(1) //Mas de 1 en aplicaciones multiplataformas
                    .expiredUrl("/login")
                    .sessionRegistry(sessionRegistry())
                .and()
                .sessionFixation() //Vulnerabilidad por si un atacante accede al id de sesion
                    .migrateSession()
                    // .migrateSession() - Spring genera otro id de sesion al detectarlo y copia los datos
                    // .newSession() - Sesion completamente nueva sin copiar datos
                    // .none() - Inhabilita la seguridad en contra de la fijacion de sesion
                .and()
                .build();
    }
    */

    //Configuracion 3
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception{
        return httpSecurity
                .csrf().disable() //Cross-Site Request Forgery, que no puedan interceptar formularios enviados del navegador al servidor. Lo deshabilito porque no va a haber forms
                .authorizeHttpRequests()
                .requestMatchers("v1/index2").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin().permitAll()
                .and()
                //Enviar las credenciales en el header de la peticion
                .httpBasic()
                .and()
                .build();
    }

    @Bean
    public SessionRegistry sessionRegistry(){
        return new SessionRegistryImpl();
    }

    public AuthenticationSuccessHandler successHandler(){
        return (((request, response, authentication) -> {
            response.sendRedirect("v1/session");
        }));
    }
}
