package com.concurso.sistema_votacion.ports.in;

/**
 * Puerto de entrada para la inicialización y gestión de las llaves EC del Sistema.
 */
public interface InicializarLlavesSistemaUseCase {

    void asegurarLlavesSistema() throws Exception;
}

