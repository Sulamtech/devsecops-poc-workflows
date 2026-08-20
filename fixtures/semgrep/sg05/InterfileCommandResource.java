package fixtures.semgrep.sg05;

import jakarta.ws.rs.QueryParam;

class InterfileCommandResource {
  void execute(@QueryParam("command") String command) throws Exception {
    InterfileCommandRunner.run(command);
  }
}
