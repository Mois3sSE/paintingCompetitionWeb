package com.concurso.sistema_votacion.ports.out;

import java.util.Optional;

/**
 * Puerto de salida para almacenar y consultar llaves públicas EC en la base de datos.
 */
public interface LlavesECRepositoryPort {

    boolean existeLlavePublicaPorUsuario(int usuarioId) throws Exception;

    void guardarLlavePublicaUsuario(int usuarioId, String llavePublicaB64) throws Exception;

    // La llave pública del pintor se lee de la BD para verificar su firma ECDSA
    Optional<String> obtenerLlavePublicaPorUsuario(int usuarioId) throws Exception;
}

