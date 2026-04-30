import com.authentication.AuthenticationService;
import com.authentication.RegisterRequestDto;
import com.customer.Customer;
import com.customer.CustomerRepository;
import com.exception.UserAlreadyExistsException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AuthenticationServiceRegisterTest {

    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private CustomerRepository customerRepository;
    @InjectMocks
    private AuthenticationService authenticationService;

    @Test
    void registerUserSuccessfullyTest(){
        //Arrange
        RegisterRequestDto mockRegisterDto = new RegisterRequestDto("Mock", "User", "mockuser@test.com", "Password12345");
        when(customerRepository.findByEmailAddress(mockRegisterDto.emailAddress()))
                .thenReturn(Optional.empty());
        when(passwordEncoder.encode(mockRegisterDto.password())).thenReturn("hashed-password");
        //Act
        authenticationService.registerUser(mockRegisterDto);
        //Assert
        verify(customerRepository).save(any(Customer.class));
    }

    @Test
    void registerUserFailureTest(){
        RegisterRequestDto mockRegisterDto = new RegisterRequestDto("Mock", "User", "mockuser@test.com", "Password12345");
        when(customerRepository.findByEmailAddress(mockRegisterDto.emailAddress()))
                .thenReturn(Optional.of(new Customer(mockRegisterDto.lastName(),
                        mockRegisterDto.firstName(), mockRegisterDto.emailAddress(), mockRegisterDto.password())));

        assertThrows(UserAlreadyExistsException.class, () -> authenticationService.registerUser(mockRegisterDto));
        verify(customerRepository, never()).save(any(Customer.class));
    }
}
