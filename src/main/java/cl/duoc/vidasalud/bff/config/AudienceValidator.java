package cl.duoc.vidasalud.bff.config;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;

/**
 * Verifica que el token haya sido emitido PARA esta API.
 * Sin esta validacion, un token valido emitido para otra
 * aplicacion del mismo tenant seria aceptado.
 */
public class AudienceValidator implements OAuth2TokenValidator<Jwt> {

    private final String audience;
    private final String audienceUri;

    public AudienceValidator(String audience) {
        this.audience = audience;
        this.audienceUri = "api://" + audience;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        List<String> audiences = jwt.getAudience();

        if (audiences != null
                && (audiences.contains(audience) || audiences.contains(audienceUri))) {
            return OAuth2TokenValidatorResult.success();
        }

        return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                "invalid_token",
                "La audiencia del token no corresponde a esta API",
                null));
    }
}