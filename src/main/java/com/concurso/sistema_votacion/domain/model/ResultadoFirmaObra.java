package com.concurso.sistema_votacion.domain.model;

/**
 * Resultado de registrar y firmar una obra con ECDSA (Integrante 2).
 */
public record ResultadoFirmaObra(
        int obraId,
        String titulo,
        String pintor,
        String nombreArchivoOriginal,
        String rutaImagenCifrada,
        int tamanoBytes,
        String algoritmo,
        String hashSha256Hex,
        int longitudFirmaBytes,
        String firmaHex,
        String firmaBase64,
        boolean verificadaConLlavePublicaBD) {
}
