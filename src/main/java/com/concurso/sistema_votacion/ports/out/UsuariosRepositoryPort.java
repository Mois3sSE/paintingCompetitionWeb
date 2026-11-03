package com.concurso.sistema_votacion.ports.out;

import java.util.Optional;

import com.concurso.sistema_votacion.domain.model.UsuarioInfo;

/**
 * Puerto de salida para consultar usuarios en la base de datos (tabla USUARIOS).
 */
public interface UsuariosRepositoryPort {

    Optional<UsuarioInfo> buscarPorId(int usuarioId) throws Exception;
}
