package fixtures.semgrep.sg05;

class InterfileCommandRunner {
  static void run(String value) throws Exception {
    // todoruleid: poc-java-command-injection
    Runtime.getRuntime().exec(value);
  }
}
