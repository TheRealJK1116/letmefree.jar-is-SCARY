

• ## 1. Windows Command Injection

  **Severity:** Critical

  Server-controlled messages are inserted into an executable batch file. Only `&` is escaped.

  ```java
  for (String msg : messages) {
      if (msg.isBlank()) {
          bat.append("echo.\r\n");
          continue;
      }

      bat.append("echo ")
         .append(msg.replace("&", "^&"))
         .append("\r\n");
  }

  Files.writeString(tmp, bat.toString());

  Runtime.getRuntime().exec(new String[]{
      "cmd", "/c", "start", "", "cmd", "/c",
      tmp.toAbsolutePath().toString()
  });
  ```

  ## 2. Server-Triggered Computer Suspension

  **Severity:** Critical

  A server packet executes an operating-system suspend command without confirmation.

  ```java
  ClientPlayNetworking.registerGlobalReceiver(ShutDownPayload.ID, (payload, context) ->
      context.client().execute(() -> {
          try {
              String os = System.getProperty("os.name", "").toLowerCase();

              if (os.contains("win")) {
                  Runtime.getRuntime().exec(
                      "rundll32.exe powrprof.dll,SetSuspendState 0,1,0"
                  );
              } else if (os.contains("mac") || os.contains("darwin")) {
                  Runtime.getRuntime().exec("pmset sleepnow");
              } else {
                  Runtime.getRuntime().exec("systemctl suspend");
              }
          } catch (Exception exception) {
              // empty catch block
          }
      })
  );
  ```

  ## 3. Public IP and Operating-System Disclosure

  **Severity:** High

  The client sends its public IP and operating-system name to the connected server.

  ```java
  ClientPlayConnectionEvents.JOIN.register((handler, sender, client) -> {
      String osName = System.getProperty("os.name", "Unknown");

      TERMINAL_EXEC.execute(() -> {
          String publicIp = HorrorClientPackets.fetchPublicIp();

          client.execute(() ->
              ClientPlayNetworking.send(new ClientInfoPayload(osName, publicIp))
          );
      });
  });
  ```

  ## 4. Hardcoded Privileged Passcode

  **Severity:** High

  The shared privileged-command passcode is embedded in every distributed JAR.

  ```java
  public class PasscodeManager {
      private static final Set<UUID> UNLOCKED =
          Collections.synchronizedSet(new HashSet());

      static final String CORRECT = "LMF2015";

      public static boolean tryUnlock(UUID id, String input) {
          if (CORRECT.equals(input.trim())) {
              UNLOCKED.add(id);
              return true;
          }

          return false;
      }
  }
  ```

  ## 5. Unvalidated Flashing Parameters

  **Severity:** Medium

  Server-controlled values can produce a zero cycle and crash the render path.

  ```java
  ScaryEyesRenderer.showFlashing(
      payload.textureType(),
      payload.flashes(),
      payload.onMs(),
      payload.offMs()
  );
  ```

  ```java
  long cycle = flashOnMs + flashOffMs;
  long phase = elapsed % cycle;
  ```
