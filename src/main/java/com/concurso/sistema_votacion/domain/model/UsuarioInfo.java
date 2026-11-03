package com.concurso.sistema_votacion.domain.model;

/**
 * Datos públicos de un usuario (sin password_hash).
 */
public record UsuarioInfo(int id, String nombreUsuario, String rol) {
}
