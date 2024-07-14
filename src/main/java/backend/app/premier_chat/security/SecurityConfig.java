package backend.app.premier_chat.security;

import backend.app.premier_chat.Models.configuration.AuthorizationStrategyConfiguration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    AuthorizationStrategyConfiguration authorizationConfig(@Value("${spring.security.strategy}") String strategy) {
        return new AuthorizationStrategyConfiguration(strategy);
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http.authorizeExchange(
                e -> e.pathMatchers("/**").permitAll()
                        .anyExchange().authenticated()
        );

        return http.build();

    }

}
