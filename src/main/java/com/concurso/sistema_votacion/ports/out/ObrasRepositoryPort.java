package com.concurso.sistema_votacion.ports.out;

import java.util.List;
import java.util.Optional;

import com.concurso.sistema_votacion.domain.model.Obra;

/**
 * Puerto de salida para registrar y consultar obras en la base de datos (tabla OBRAS).
 */
public interface ObrasRepositoryPort {

    int insertarObra(String titulo, int autorId, String nombreArchivoOriginal,
            String rutaImagenCifrada, String firmaEcdsaPintorB64) throws Exception;

    Optional<Obra> buscarPorId(int obraId) throws Exception;

    List<Obra> listarObras() throws Exception;

    List<Obra> listarObrasPorAutor(int autorId) throws Exception;
}
