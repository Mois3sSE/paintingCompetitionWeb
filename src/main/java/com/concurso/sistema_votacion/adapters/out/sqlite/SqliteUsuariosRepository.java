package com.concurso.sistema_votacion.adapters.out.sqlite;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

import com.concurso.sistema_votacion.domain.model.UsuarioInfo;
import com.concurso.sistema_votacion.ports.out.UsuariosRepositoryPort;

@Repository
public class SqliteUsuariosRepository implements UsuariosRepositoryPort {

    @Value("${spring.datasource.url:jdbc:sqlite:db/votacion.db}")
    private String dbUrl;

    @Override
    public Optional<UsuarioInfo> buscarPorId(int usuarioId) throws Exception {
        try (Connection conn = DriverManager.getConnection(dbUrl);
                PreparedStatement ps = conn.prepareStatement(
                        "SELECT id, nombre_usuario, rol FROM USUARIOS WHERE id = ?")) {
            ps.setInt(1, usuarioId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(new UsuarioInfo(
                            rs.getInt("id"),
                            rs.getString("nombre_usuario"),
                            rs.getString("rol")));
                }
                return Optional.empty();
            }
        }
    }
}
