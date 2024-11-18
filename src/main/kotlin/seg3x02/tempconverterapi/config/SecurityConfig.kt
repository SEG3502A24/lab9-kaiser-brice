package seg3x02.tempconverterapi.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain

@Configuration
@EnableWebSecurity
class SecurityConfig {

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        return BCryptPasswordEncoder()
    }

    @Bean
    fun userDetailsService(passwordEncoder: PasswordEncoder): UserDetailsService {
        val user1 = User.withUsername("user1")
            .password(passwordEncoder.encode("pass1"))
            .roles("USER")
            .build()

        val user2 = User.withUsername("user2")
            .password(passwordEncoder.encode("pass2"))
            .roles("USER")
            .build()

        return InMemoryUserDetailsManager(user1, user2)
    }

    @Bean
    @Throws(Exception::class)
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
         .authorizeHttpRequests { auth -> auth.anyRequest().authenticated() }
         .formLogin {formLogin -> formLogin.loginPage("/login").permitAll() }
         .logout(Customizer.withDefaults())
         return http.build()
    }
}
