package cl.duoc.vidasalud.bff.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.time.Instant;
import java.util.Map;

@Component
public class SecurityErrorHandlers {

    private final ObjectMapper mapper = new ObjectMapper();

    /** 401: no hay token, esta expirado, la firma no valida,
     *  el issuer no corresponde o la audiencia no es esta API. */
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return (request, response, authException) ->
                write(response, HttpServletResponse.SC_UNAUTHORIZED,
                      "unauthorized",
                      "Token ausente, expirado o no valido",
                      request.getRequestURI());
    }

    /** 403: el token es valido, pero el usuario no tiene
     *  el rol o el scope necesario para este endpoint. */
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, accessDeniedException) ->
                write(response, HttpServletResponse.SC_FORBIDDEN,
                      "forbidden",
                      "No tiene permisos para acceder a este recurso",
                      request.getRequestURI());
    }

    private void write(HttpServletResponse response, int status,
                       String error, String message, String path) throws java.io.IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        mapper.writeValue(response.getWriter(), Map.of(
                "timestamp", Instant.now().toString(),
                "status", status,
                "error", error,
                "message", message,
                "path", path));
    }
}