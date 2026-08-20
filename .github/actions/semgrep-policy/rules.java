import jakarta.ws.rs.QueryParam;
import static java.lang.Runtime.getRuntime;

class RuleCases {
  void direct(@QueryParam("command") String command) throws Exception {
    // ruleid: poc-java-command-injection
    Runtime.getRuntime().exec(command);
  }

  void staticImport(@QueryParam("command") String command) throws Exception {
    // ruleid: poc-java-command-injection
    getRuntime().exec(command);
  }

  void processBuilder(@QueryParam("command") String command) {
    // ruleid: poc-java-command-injection
    new ProcessBuilder(command);
  }

  void sameFileWrapper(@QueryParam("command") String command) throws Exception {
    executeThroughWrapper(command);
  }

  private void executeThroughWrapper(String value) throws Exception {
    // todoruleid: poc-java-command-injection
    Runtime.getRuntime().exec(value);
  }

  void fixed() throws Exception {
    // ok: poc-java-command-injection
    Runtime.getRuntime().exec("date");
  }
}
