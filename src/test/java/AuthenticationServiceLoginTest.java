import com.authentication.AuthenticationService;
import com.authentication.LoginRequestDto;
import com.customer.Customer;
import com.customer.CustomerRepository;
import com.secuirty.JwtService;
import com.secuirty.RefreshToken;
import com.secuirty.RefreshTokenRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.time.Duration;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AuthenticationServiceLoginTest {

    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private JwtService jwtService;
    @Mock
    private CustomerRepository customerRepository;
    @Mock
    private RefreshTokenRepository refreshTokenRepository;
    @InjectMocks
    private AuthenticationService authenticationService;

    @Test
    void loginUserSuccessfulTest(){
        LoginRequestDto mockLoginRequest = new LoginRequestDto("mockemailaddress@test.com", "Password12345");
        when(authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(mockLoginRequest.emailAddress(), mockLoginRequest.password())))
                .thenReturn(mock(Authentication.class));
        when(customerRepository.findByEmailAddress(mockLoginRequest.emailAddress())).thenReturn(Optional.of(new Customer()));
        when(jwtService.createToken(mockLoginRequest.emailAddress())).thenReturn("Mock-Jwt");

        authenticationService.loginUser(mockLoginRequest);
        verify(jwtService).issueResponseCookie("token","Mock-Jwt", Duration.ofHours(1));
        verify(jwtService).issueResponseCookie(eq("refreshToken"), any(), any());
        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    void loginUserFailureTest(){
        LoginRequestDto mockLoginRequest = new LoginRequestDto("mockemailaddress@test.com", "Password12345");
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(BadCredentialsException.class);

        assertThrows(BadCredentialsException.class, () -> authenticationService.loginUser(mockLoginRequest));
        verify(jwtService, never()).createToken(any());
        verify(jwtService, never()).issueResponseCookie(any(), any(), any());
    }

}
