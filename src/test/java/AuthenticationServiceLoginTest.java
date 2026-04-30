import com.authentication.AuthenticationService;
import com.authentication.LoginRequestDto;
import com.secuirty.JwtService;
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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AuthenticationServiceLoginTest {

    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private JwtService jwtService;
    @InjectMocks
    private AuthenticationService authenticationService;

    @Test
    void loginUserSuccessfulTest(){
        LoginRequestDto mockLoginRequest = new LoginRequestDto("mockemailaddress@test.com", "Password12345");
        when(authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(mockLoginRequest.emailAddress(), mockLoginRequest.password())))
                .thenReturn(mock(Authentication.class));
        when(jwtService.createToken(mockLoginRequest.emailAddress())).thenReturn("Mock-Jwt");

        authenticationService.loginUser(mockLoginRequest);
        verify(jwtService).issueJwtCookie("token","Mock-Jwt", Duration.ofHours(1));
    }

    @Test
    void loginUserFailureTest(){
        LoginRequestDto mockLoginRequest = new LoginRequestDto("mockemailaddress@test.com", "Password12345");
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(BadCredentialsException.class);

        assertThrows(BadCredentialsException.class, () -> authenticationService.loginUser(mockLoginRequest));
        verify(jwtService, never()).createToken(any());
        verify(jwtService, never()).issueJwtCookie(any(), any(), any());
    }

}
