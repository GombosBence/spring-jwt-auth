import com.authentication.AuthenticationService;
import com.authentication.CookieResponseDto;
import com.customer.Customer;
import com.exception.RefreshTokenExpiredException;
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
public class AuthenticationServiceNewJwtTest {

    @Mock
    private JwtService jwtService;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @InjectMocks
    private AuthenticationService authenticationService;

    @Test
    void successfulRefreshTest(){
        HttpServletRequest request = mock(HttpServletRequest.class);
        Cookie[] mockCookies = {new Cookie("refreshToken", "mock-cookie-value")};
        when(request.getCookies()).thenReturn(mockCookies);
        Customer mockCustomer = new Customer("test", "user", "test@test.com", "hashed-password");
        RefreshToken mockToken = new RefreshToken("mock-token", Instant.now().plus(Duration.ofDays(7)), mockCustomer);
        when(refreshTokenRepository.findByHashedValue(any())).thenReturn(Optional.of(mockToken));
        when(jwtService.createToken(any())).thenReturn("mock-jwt");
        when(jwtService.issueResponseCookie(any(), any(), any())).thenReturn(mock(ResponseCookie.class));

        CookieResponseDto response = authenticationService.getNewJwt(request);

        assert(mockToken.isRevoked());
        verify(refreshTokenRepository, times(2)).save(any(RefreshToken.class));
        assert(response != null);
    }

    @Test
    void tokenNotFoundInRequestTest(){
        HttpServletRequest request = mock(HttpServletRequest.class);
        Cookie[] mockEmptyCookies = {};
        when(request.getCookies()).thenReturn(mockEmptyCookies);

        assertThrows(RefreshTokenNotFoundException.class, () -> authenticationService.getNewJwt(request));
        verify(refreshTokenRepository, never()).save(any());
    }

    @Test
    void tokenNotFoundInDatabaseTest(){
        HttpServletRequest request = mock(HttpServletRequest.class);
        Cookie[] mockCookies = {new Cookie("refreshToken", "mock-cookie-value")};
        when(request.getCookies()).thenReturn(mockCookies);
        when(refreshTokenRepository.findByHashedValue(any())).thenReturn(Optional.empty());

        assertThrows(RefreshTokenNotFoundException.class, () -> authenticationService.getNewJwt(request));
        verify(refreshTokenRepository, never()).save(any());

    }

    @Test
    void tokenExpiredOrRevokedTest(){
        HttpServletRequest request = mock(HttpServletRequest.class);
        Cookie[] mockCookies = {new Cookie("refreshToken", "mock-cookie-value")};
        when(request.getCookies()).thenReturn(mockCookies);
        RefreshToken mockToken = new RefreshToken("mockValue", Instant.now().minus(Duration.ofDays(1)), new Customer());
        when(refreshTokenRepository.findByHashedValue(any())).thenReturn(Optional.of(mockToken));

        assertThrows(RefreshTokenExpiredException.class, () -> authenticationService.getNewJwt(request));
        verify(refreshTokenRepository, never()).save(any());
    }
}
