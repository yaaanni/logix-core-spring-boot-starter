package io.github.yaaanni.logix;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.CollectionUtils;
import org.springframework.web.servlet.HandlerExceptionResolver;

@AutoConfiguration
@EnableConfigurationProperties(PlatformConfig.class)
@ConditionalOnProperty(
        prefix = "platform.security",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
)
public class ResourceServerAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public DelegatingAuthenticationEntryPoint delegatingAuthenticationEntryPoint(
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver
    ) {
        return new DelegatingAuthenticationEntryPoint(resolver);
    }

    @Bean
    @ConditionalOnMissingBean
    public DelegatingAccessDeniedHandler delegatingAccessDeniedHandler(
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver
    ) {
        return new DelegatingAccessDeniedHandler(resolver);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, DelegatingAuthenticationEntryPoint entryPoint,
                                                   DelegatingAccessDeniedHandler accessDeniedHandler, PlatformConfig config) throws Exception {

        PlatformConfig.Security security = config.security();

        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(auth -> {
                    if (!CollectionUtils.isEmpty(security.publicRules())) {
                        for (var rule : security.publicRules()) {
                            if (rule.method() != null) {
                                auth.requestMatchers(rule.method(), rule.pattern()).permitAll();
                            } else {
                                auth.requestMatchers(rule.pattern()).permitAll();
                            }
                        }
                    }

                    if (!CollectionUtils.isEmpty(security.roleRules())) {
                        for (var rule : security.roleRules()) {
                            String[] roles = rule.roles().toArray(String[]::new);

                            if (rule.method() != null) {
                                auth.requestMatchers(rule.method(), rule.pattern()).hasAnyRole(roles);
                            } else {
                                auth.requestMatchers(rule.pattern()).hasAnyRole(roles);
                            }
                        }
                    }

                    auth.anyRequest().authenticated();
                })
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(new KeycloakJwtAuthenticationConverter()))
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                );

        return http
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                )
                .build();
    }
}
