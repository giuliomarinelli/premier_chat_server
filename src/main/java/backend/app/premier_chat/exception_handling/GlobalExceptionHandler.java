package backend.app.premier_chat.exception_handling;

import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.support.WebExchangeBindException;
import reactor.core.publisher.Mono;

import java.util.stream.Collectors;

@Component
@RestControllerAdvice
@Order(-2)
public class GlobalExceptionHandler {

    @ExceptionHandler(WebExchangeBindException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<ResponseEntity<ErrorResDto>> handleValidationExceptions(WebExchangeBindException e) {
        String message = e.getFieldErrors().parallelStream()
                .map(DefaultMessageSourceResolvable::getDefaultMessage)
                .collect(Collectors.joining(". ", "", "."));
        return handleBadRequestException(new BadRequestException(message));

    }

    @ExceptionHandler(BadRequestException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<ResponseEntity<ErrorResDto>> handleBadRequestException(BadRequestException e) {
        ErrorResDto errorResDto = new ErrorResDto(
                HttpStatus.BAD_REQUEST,
                "Bad Request",
                e.getMessage()
        );
        return Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResDto));
    }

    @ExceptionHandler(UnauthorizedException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public Mono<ResponseEntity<ErrorResDto>> handleBadRequestException(UnauthorizedException e) {
        ErrorResDto errorResDto = new ErrorResDto(
                HttpStatus.UNAUTHORIZED,
                "Unauthorized",
                e.getMessage()
        );
        return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResDto));
    }

    @ExceptionHandler(ForbiddenException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public Mono<ResponseEntity<ErrorResDto>> handleBadRequestException(ForbiddenException e) {
        ErrorResDto errorResDto = new ErrorResDto(
                HttpStatus.FORBIDDEN,
                "Forbidden",
                e.getMessage()
        );
        return Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorResDto));
    }

    @ExceptionHandler(NotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<ResponseEntity<ErrorResDto>> handleBadRequestException(NotFoundException e) {
        ErrorResDto errorResDto = new ErrorResDto(
                HttpStatus.NOT_FOUND,
                "Not Found",
                e.getMessage()
        );
        return Mono.just(ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResDto));
    }

}
