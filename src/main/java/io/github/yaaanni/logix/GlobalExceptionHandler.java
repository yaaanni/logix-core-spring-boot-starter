package io.github.yaaanni.logix;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.*;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@AutoConfiguration
@RestControllerAdvice
@Order(Ordered.LOWEST_PRECEDENCE)
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleUncaughtException(Exception ex, HttpServletRequest req) {
        log.error("Unhandled exception at {}: ", req.getRequestURI(), ex);

        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An unexpected error occurred on the server. Please try again later."
        );
        problem.setTitle("Internal Server Error");
        problem.setInstance(URI.create(req.getRequestURI()));
        problem.setProperty("errorCode", "INTERNAL_SERVER_ERROR");
        return problem;
    }

    @ExceptionHandler(AuthenticationException.class)
    public ProblemDetail handleAuthentication(AuthenticationException ex, HttpServletRequest req) {
        log.debug("Authentication failed at {}: {}", req.getRequestURI(), ex.getMessage());

        String errorCode = resolveErrorCode(ex);

        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, ex.getMessage());
        problem.setTitle("Unauthorized");
        problem.setInstance(URI.create(req.getRequestURI()));
        problem.setProperty("errorCode", errorCode);
        return problem;
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ProblemDetail handleAccessDenied(AccessDeniedException ex, HttpServletRequest req) {
        log.debug("Access denied at {}: {}", req.getRequestURI(), ex.getMessage());

        String errorCode = resolveAccessDeniedErrorCode(ex);

        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.FORBIDDEN,
                "Access Denied: You don't have enough permissions"
        );
        problem.setTitle("Forbidden");
        problem.setInstance(URI.create(req.getRequestURI()));
        problem.setProperty("errorCode", errorCode);
        return problem;
    }

    @ExceptionHandler(BusinessException.class)
    public ProblemDetail handleBusinessException(BusinessException ex, HttpServletRequest req) {
        log.warn("Business exception at {}: [{}] {}", req.getRequestURI(), ex.getErrorCode(), ex.getMessage());

        ProblemDetail problem = ProblemDetail.forStatusAndDetail(ex.getStatus(), ex.getMessage());
        problem.setTitle(ex.getErrorCode());
        problem.setInstance(URI.create(req.getRequestURI()));
        problem.setProperty("errorCode", ex.getErrorCode());
        return problem;
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex,
            HttpHeaders headers,
            HttpStatusCode status,
            WebRequest request) {

        String path = ((ServletWebRequest) request).getRequest().getRequestURI();
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(error ->
                errors.put(error.getField(), error.getDefaultMessage())
        );

        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Validation failed for request body");
        problem.setTitle("Validation Failed");
        problem.setInstance(URI.create(path));
        problem.setProperty("errorCode", "VALIDATION_FAILED");
        problem.setProperty("invalidFields", errors);

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
    }

    private String resolveErrorCode(AuthenticationException ex) {
        Throwable cause = ex.getCause() != null ? ex.getCause() : ex;

        if (ex instanceof OAuth2AuthenticationException oAuth2Ex) {
            String oAuth2Code = oAuth2Ex.getError().getErrorCode();
            if ("invalid_token".equals(oAuth2Code) && ex.getMessage().contains("expired")) {
                return "TOKEN_EXPIRED";
            }
        }

        return switch (cause) {
            case BadCredentialsException e -> "BAD_CREDENTIALS";
            case DisabledException e -> "ACCOUNT_DISABLED";
            case LockedException e -> "ACCOUNT_LOCKED";
            case InsufficientAuthenticationException e -> "AUTHENTICATION_REQUIRED";

            case JwtValidationException e -> "TOKEN_EXPIRED";
            case BadJwtException e -> "TOKEN_INVALID";
            case JwtException e -> "TOKEN_INVALID";

            default -> "UNAUTHORIZED";
        };
    }

    private String resolveAccessDeniedErrorCode(AccessDeniedException ex) {
        Throwable cause = ex.getCause() != null ? ex.getCause() : ex;

        return switch (cause) {
            case org.springframework.security.web.csrf.InvalidCsrfTokenException e -> "CSRF_TOKEN_INVALID";
            case org.springframework.security.web.csrf.MissingCsrfTokenException e -> "CSRF_TOKEN_MISSING";
            default -> "ACCESS_DENIED";
        };
    }
}