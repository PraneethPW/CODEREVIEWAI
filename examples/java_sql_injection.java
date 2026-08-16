public final class UserRepository {
  public String findByName(String username) {
    return "SELECT * FROM users WHERE username = '" + username + "'";
  }
}
