package com.project.aura.controllers;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

import com.project.aura.dto.LoginRequest;
import com.project.aura.dto.LoginResponse;
import com.project.aura.jwt.JwtUtil;
import com.project.aura.models.Contacto;
import com.project.aura.models.Usuario;
import com.project.aura.repositories.UsuarioRepository;
import com.project.aura.services.UsuarioService;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UsuarioRepository usuarioRepository;
    private final UsuarioService usuarioService;
    private final JwtUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest request) {
        try {
            authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    request.getEmail(),
                    request.getPassword()
                )
            );
        } catch (AuthenticationException e) {
            return ResponseEntity.status(401).build();
        }

        Usuario usuario = usuarioRepository
            .findByContactoEmail(request.getEmail())
            .orElseThrow();

        String token = jwtUtil.generarToken(
            usuario.getContacto().getEmail(),
            usuario.getRol().name()
        );

        return ResponseEntity.ok(LoginResponse.builder()
            .token(token)
            .nombre(usuario.getNombre())
            .rol(usuario.getRol().name())
            .build());
    }

    @PostMapping("/register")
    public ResponseEntity<LoginResponse> register(
        @Valid @RequestBody Usuario request) {

    Contacto contacto = Contacto.builder()
        .email(request.getContacto().getEmail())
        .telefono(request.getContacto().getTelefono())
        .build();

    Usuario usuario = Usuario.builder()
        .nombre(request.getNombre())
        .password(request.getPassword())
        .rol(request.getRol())
        .contacto(contacto)
        .build();

    usuarioService.crear(usuario);

    String token = jwtUtil.generarToken(
        contacto.getEmail(),
        usuario.getRol().name()
    );

    return ResponseEntity.ok(LoginResponse.builder()
        .token(token)
        .nombre(usuario.getNombre())
        .rol(usuario.getRol().name())
        .build());
}
}
