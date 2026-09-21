// Deliberately vulnerable Java (test fixture, never deploy).
import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.sql.Statement;

public class UserDao {
    public ResultSet find(Statement stmt, String name) throws Exception {
        return stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'"); // SQL injection
    }

    public Object load(java.io.InputStream in) throws Exception {
        return new ObjectInputStream(in).readObject(); // unsafe deserialization
    }

    public byte[] digest(byte[] data) throws Exception {
        return MessageDigest.getInstance("MD5").digest(data); // weak hash
    }
}
