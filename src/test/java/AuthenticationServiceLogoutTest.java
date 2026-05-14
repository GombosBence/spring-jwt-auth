import com.authentication.AuthenticationService;
import com.authentication.CookieResponseDto;
import com.customer.Customer;
import com.exception.RefreshTokenNotFoundException;
import com.secuirty.JwtService;
import com.secuirty.RefreshToken;
import com.secuirty.RefreshTokenRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseCookie;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AuthenticationServiceLogoutTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private JwtService jwtService;

    @InjectMocks
    private AuthenticationService authenticationService;

    @Test
    void successfulLogoutTest(){
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        Cookie[] cookies = {new Cookie("refreshToken", "mock-token-value")};
        when(mockRequest.getCookies()).thenReturn(cookies);
        RefreshToken mockToken = new RefreshToken("mockValue", Instant.now().plus(Duration.ofDays(3)), new Customer());
        when(refreshTokenRepository.findByHashedValue(any())).thenReturn(Optional.of(mockToken));
        when(jwtService.issueResponseCookie(any(), any(), any())).thenReturn(mock(ResponseCookie.class));

        CookieResponseDto responseDto = authenticationService.logout(mockRequest);

        assert(mockToken.isRevoked());
        assert(responseDto != null);
        verify(refreshTokenRepository).save(any());
    }

    @Test
    void refreshTokenNotFoundInRequestTest(){
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        Cookie[] cookies = {};
        when(mockRequest.getCookies()).thenReturn(cookies);

        assertThrows(RefreshTokenNotFoundException.class, () -> authenticationService.logout(mockRequest));
        verify(refreshTokenRepository, never()).save(any());
    }

    @Test
    void refreshTokenNotFoundInDbTest(){
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        Cookie[] cookies = {new Cookie("refreshToken", "mock-token-value")};
        when(mockRequest.getCookies()).thenReturn(cookies);
        when(refreshTokenRepository.findByHashedValue(any())).thenReturn(Optional.empty());

        assertThrows(RefreshTokenNotFoundException.class, () -> authenticationService.logout(mockRequest));
        verify(refreshTokenRepository, never()).save(any());
    }

}
