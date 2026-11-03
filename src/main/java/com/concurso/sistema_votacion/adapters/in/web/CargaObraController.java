package com.concurso.sistema_votacion.adapters.in.web;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.concurso.sistema_votacion.domain.crypto.ModuloConfidencialidadAES;

@RestController
@RequestMapping("/api/obras")
public class CargaObraController {

    @Autowired
    private ModuloConfidencialidadAES moduloConfidencialidadAES;

    @PostMapping("/cifrar-integrante1")
    public ResponseEntity<?> cifrarObra(
            @RequestParam("pintor") String nombrePintor,
            @RequestParam("titulo") String titulo,
            @RequestParam("imagen") MultipartFile imagenFile) {
        try {
            Map<String, Object> resultado = moduloConfidencialidadAES.procesarObraIntegrante1(
                    nombrePintor, 
                    titulo,
                    imagenFile.getBytes(), 
                    imagenFile.getOriginalFilename()
            );
            return ResponseEntity.ok(resultado);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().body(Map.of("error", "Error criptográfico: " + e.getMessage()));
        }
    }
}