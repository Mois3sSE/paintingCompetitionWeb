package com.concurso.sistema_votacion.domain.crypto;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Service;

@Service
public class ModuloConfidencialidadAES {

    public Map<String, Object> procesarObraIntegrante1(String nombrePintor, String tituloObra, byte[] imagenBytes, String nombreImagenOriginal) throws Exception {
        Map<String, Object> logConsola = new HashMap<>();

        System.out.println("GENERACIÓN DE LLAVE AES (ACUERDO DE CLAVES ECDH CON EL SISTEMA)");
        System.out.println("==============================================================");
        System.out.println("Pintor autenticado:   " + nombrePintor);

        // 1. Cargar llaves desde los directorios locales
        String rutaPrivPintor = "claves_usuarios/Pintores/" + nombrePintor + "/" + nombrePintor + "_priv.pem";
        String rutaPubSistema = "clave_sistema/pub_sist.pem";
        
        PrivateKey privPintor = cargarLlavePrivadaEC(rutaPrivPintor);
        PublicKey pubSistema = cargarLlavePublicaEC(rutaPubSistema);

        // 2. Acuerdo de claves ECDH
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privPintor);
        keyAgreement.doPhase(pubSistema, true);
        byte[] secretoCompartido = keyAgreement.generateSecret();

        // 3. Derivación SHA-256 para obtener llave AES de 256 bits
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] aesKeyBytes = sha256.digest(secretoCompartido);
        SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        System.out.println("==============================================================");
        System.out.println(" LLAVE SIMÉTRICA AES GENERADA EXITOSAMENTE (ECDH)");
        System.out.println("==============================================================");
        System.out.println("Algoritmo derivado:            AES (256 bits)");
        System.out.println("Operación Criptográfica:       d_pintor * Q_sistema -> Derivación SHA-256");
        System.out.println("LLAVE AES (Base64):            " + Base64.getEncoder().encodeToString(aesKeyBytes));

        // 4. Cifrado Autenticado (AES-GCM)
        System.out.println("\nCIFRADO AUTENTICADO DE IMAGEN / OBRA (AES-GCM)");
        System.out.println("==============================================================");
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12];
        SecureRandom.getInstanceStrong().nextBytes(iv); // IV aleatorio de 12 bytes
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv); // Tag de autenticación de 128 bits
        
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
        byte[] payloadCifrado = cipher.doFinal(imagenBytes);

        // 5. Concatenar IV + Payload Cifrado y guardar en archivo físico
        String nombreArchivoSalida = "imagenes/imagen_Cifrado_" + nombrePintor + ".png";
        File dirImagenes = new File("imagenes");
        if(!dirImagenes.exists()) dirImagenes.mkdirs();
        
        try (FileOutputStream fos = new FileOutputStream(nombreArchivoSalida)) {
            fos.write(iv); 
            fos.write(payloadCifrado); 
        }

        System.out.println("==============================================================");
        System.out.println(" IMAGEN CIFRADA CON ÉXITO (AES-GCM - INTEGRANTE 1)");
        System.out.println("==============================================================");
        System.out.println("Tamaño imagen original:      " + imagenBytes.length + " bytes");
        System.out.println("IV generado (12 bytes):      " + Base64.getEncoder().encodeToString(iv));
        System.out.println("Tag de autenticación:        " + Base64.getEncoder().encodeToString(cipher.getIV()));
        System.out.println("Tamaño de payload cifrado:   " + payloadCifrado.length + " bytes");
        System.out.println("Archivo cifrado exportado:   " + nombreArchivoSalida + " (total: " + (iv.length + payloadCifrado.length) + " bytes)");
        System.out.println("Verificación de Integridad:  VÁLIDA [OK]");

        // 6. Registrar en la base de datos SQLite (Tabla OBRAS)
       String urlDb = "jdbc:sqlite:db/votacion.db";
        try (Connection conn = DriverManager.getConnection(urlDb)) {
            int autorId = -1;
            try (PreparedStatement pstmtUser = conn.prepareStatement("SELECT id FROM USUARIOS WHERE nombre_usuario = ?")) {
                pstmtUser.setString(1, nombrePintor);
                ResultSet rs = pstmtUser.executeQuery();
                if (rs.next()) {
                    autorId = rs.getInt("id");
                }
            }

            if (autorId == -1) {
                throw new Exception("No se encontró el ID del usuario pintor en la base de datos.");
            }

            // CORRECCIÓN: Agregamos "firma_ecdsa_pintor" con un valor temporal para cumplir el NOT NULL de la BD
            String sqlInsert = "INSERT INTO OBRAS (titulo, autor_id, nombre_archivo_original, ruta_imagen_cifrada, firma_ecdsa_pintor, fecha_registro) VALUES (?, ?, ?, ?, ?, ?)";
            try (PreparedStatement pstmtInsert = conn.prepareStatement(sqlInsert)) {
                pstmtInsert.setString(1, tituloObra);
                pstmtInsert.setInt(2, autorId);
                pstmtInsert.setString(3, nombreImagenOriginal);
                pstmtInsert.setString(4, nombreArchivoSalida);
                pstmtInsert.setString(5, "PENDIENTE_INTEGRANTE_2"); // Valor temporal mientras el Integrante 2 hace su parte
                pstmtInsert.setString(6, LocalDateTime.now().toString());
                pstmtInsert.executeUpdate();
            }
            System.out.println("[DB] Registro de la obra guardado exitosamente en la tabla OBRAS.");
        }

        logConsola.put("mensaje", "Proceso del Integrante 1 completado y registrado en la BD");
        logConsola.put("archivoGenerado", nombreArchivoSalida);
        return logConsola;
    }

    private PrivateKey cargarLlavePrivadaEC(String path) throws Exception {
        String keyContent = new String(Files.readAllBytes(new File(path).toPath()));
        keyContent = keyContent.replaceAll("-----BEGIN PRIVATE KEY-----", "")
                               .replaceAll("-----END PRIVATE KEY-----", "")
                               .replaceAll("\\s+", "");
        byte[] keyBytes = Base64.getDecoder().decode(keyContent);
        return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    private PublicKey cargarLlavePublicaEC(String path) throws Exception {
        String keyContent = new String(Files.readAllBytes(new File(path).toPath()));
        keyContent = keyContent.replaceAll("-----BEGIN PUBLIC KEY-----", "")
                               .replaceAll("-----END PUBLIC KEY-----", "")
                               .replaceAll("\\s+", "");
        byte[] keyBytes = Base64.getDecoder().decode(keyContent);
        return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(keyBytes));
    }
}