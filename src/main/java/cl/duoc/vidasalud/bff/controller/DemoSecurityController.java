package cl.duoc.vidasalud.bff.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Endpoints de verificacion de la autorizacion por rol y por scope.
 * En la Fase 3 estos se reemplazan por los controladores reales
 * que reenvian a los microservicios de dominio.
 */
@RestController
@RequestMapping("/api/demo")
public class DemoSecurityController {

    @GetMapping("/admin")
    @PreAuthorize("hasRole('Admin')")
    public Map<String, String> soloAdmin() {
        return Map.of("mensaje", "Acceso permitido: rol Admin");
    }

    @GetMapping("/recepcion")
    @PreAuthorize("hasAnyRole('Admin', 'Recepcionista')")
    public Map<String, String> adminORecepcion() {
        return Map.of("mensaje", "Acceso permitido: rol Admin o Recepcionista");
    }

    @GetMapping("/lectura")
    @PreAuthorize("hasAuthority('SCOPE_Appointments.Read')")
    public Map<String, String> requiereScope() {
        return Map.of("mensaje", "Acceso permitido: scope Appointments.Read");
    }
}