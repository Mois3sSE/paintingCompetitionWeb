package com.concurso.sistema_votacion.domain.model;

/**
 * Entidad de dominio que representa un renglón de la tabla OBRAS.
 *
 * @param id                    ID autoincremental de la obra.
 * @param titulo                Título de la obra.
 * @param autorId               ID del pintor (USUARIOS.id).
 * @param autorNombre           Nombre de usuario del pintor.
 * @param nombreArchivoOriginal Nombre y extensión original (ej. mona.png).
 * @param rutaImagenCifrada     Ruta local de la imagen cifrada [IV + Cipher + Tag].
 * @param firmaEcdsaPintorB64   Firma SHA256withECDSA del pintor en Base64.
 * @param fechaRegistro         Fecha de subida.
 */
public record Obra(
        int id,
        String titulo,
        int autorId,
        String autorNombre,
        String nombreArchivoOriginal,
        String rutaImagenCifrada,
        String firmaEcdsaPintorB64,
        String fechaRegistro) {
}
