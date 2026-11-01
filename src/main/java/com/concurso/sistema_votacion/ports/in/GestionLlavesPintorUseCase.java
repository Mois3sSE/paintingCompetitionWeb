package com.concurso.sistema_votacion.ports.in;

/**
 * Puerto de entrada para la gestión de llaves EC de los Pintores.
 */
public interface GestionLlavesPintorUseCase {

    void asegurarLlavesPintor(int usuarioId, String nombreUsuario) throws Exception;
}

