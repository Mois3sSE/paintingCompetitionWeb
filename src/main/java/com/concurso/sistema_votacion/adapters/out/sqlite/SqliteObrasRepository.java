package com.concurso.sistema_votacion.adapters.out.sqlite;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

import com.concurso.sistema_votacion.domain.model.Obra;
import com.concurso.sistema_votacion.ports.out.ObrasRepositoryPort;

@Repository
public class SqliteObrasRepository implements ObrasRepositoryPort {

    private static final String SELECT_OBRAS =
            "SELECT o.id, o.titulo, o.autor_id, u.nombre_usuario AS autor_nombre, o.nombre_archivo_original, " +
            "o.ruta_imagen_cifrada, o.firma_ecdsa_pintor, o.fecha_registro " +
            "FROM OBRAS o JOIN USUARIOS u ON u.id = o.autor_id ";

    @Value("${spring.datasource.url:jdbc:sqlite:db/votacion.db}")
    private String dbUrl;

    @Override
    public int insertarObra(String titulo, int autorId, String nombreArchivoOriginal,
            String rutaImagenCifrada, String firmaEcdsaPintorB64) throws Exception {
        try (Connection conn = DriverManager.getConnection(dbUrl);
                PreparedStatement ps = conn.prepareStatement(
                        "INSERT INTO OBRAS (titulo, autor_id, nombre_archivo_original, ruta_imagen_cifrada, " +
                        "firma_ecdsa_pintor, fecha_registro) VALUES (?, ?, ?, ?, ?, datetime('now', 'localtime'))",
                        Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, titulo);
            ps.setInt(2, autorId);
            ps.setString(3, nombreArchivoOriginal);
            ps.setString(4, rutaImagenCifrada);
            ps.setString(5, firmaEcdsaPintorB64);
            ps.executeUpdate();

            try (ResultSet keys = ps.getGeneratedKeys()) {
                if (keys.next()) {
                    return keys.getInt(1);
                }
                throw new IllegalStateException("No se pudo obtener el ID de la nueva obra.");
            }
        }
    }

    @Override
    public Optional<Obra> buscarPorId(int obraId) throws Exception {
        try (Connection conn = DriverManager.getConnection(dbUrl);
                PreparedStatement ps = conn.prepareStatement(SELECT_OBRAS + "WHERE o.id = ?")) {
            ps.setInt(1, obraId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? Optional.of(mapearObra(rs)) : Optional.empty();
            }
        }
    }

    @Override
    public List<Obra> listarObras() throws Exception {
        try (Connection conn = DriverManager.getConnection(dbUrl);
                PreparedStatement ps = conn.prepareStatement(SELECT_OBRAS + "ORDER BY o.id")) {
            return leerObras(ps);
        }
    }

    @Override
    public List<Obra> listarObrasPorAutor(int autorId) throws Exception {
        try (Connection conn = DriverManager.getConnection(dbUrl);
                PreparedStatement ps = conn.prepareStatement(SELECT_OBRAS + "WHERE o.autor_id = ? ORDER BY o.id")) {
            ps.setInt(1, autorId);
            return leerObras(ps);
        }
    }

    private List<Obra> leerObras(PreparedStatement ps) throws SQLException {
        List<Obra> obras = new ArrayList<>();
        try (ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                obras.add(mapearObra(rs));
            }
        }
        return obras;
    }

    private Obra mapearObra(ResultSet rs) throws SQLException {
        return new Obra(
                rs.getInt("id"),
                rs.getString("titulo"),
                rs.getInt("autor_id"),
                rs.getString("autor_nombre"),
                rs.getString("nombre_archivo_original"),
                rs.getString("ruta_imagen_cifrada"),
                rs.getString("firma_ecdsa_pintor"),
                rs.getString("fecha_registro"));
    }
}
