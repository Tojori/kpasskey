# polkitd 127 aborts on `unix-session` subjects (polkit-org/polkit#699)

Found while developing kpasskey (2026-10-08). Upstream issue: <https://github.com/polkit-org/polkit/issues/699> (its reproducer needs a mocked logind). kpasskey works around it by using a `unix-process` subject (see `src/verification/polkit_verifier.cpp`).


Additional data point: this reproduces on a stock system **without any logind mock**, as an unprivileged user with a real graphical logind session, so it is an unprivileged local DoS of polkitd.

**Environment**
- CachyOS (Arch based), polkit `127-3.1`, systemd logind, KDE Plasma 6.7.5 (Wayland), polkit-kde-agent running
- Caller: unprivileged user (uid 1000), process running under `user@1000.service` (not inside the session scope)

**Reproducer** (session `7` is the caller's own active graphical session, from `loginctl` / `org.freedesktop.login1.User.Display`; the action is a plain custom action with `auth_self` defaults):

```sh
busctl --system call org.freedesktop.PolicyKit1 /org/freedesktop/PolicyKit1/Authority \
  org.freedesktop.PolicyKit1.Authority CheckAuthorization '(sa{sv})sa{ss}us' \
  unix-session 1 session-id s 7  org.kde.kpasskey.verify-user  0  1 ""
# -> "Call failed: Remote peer disconnected"
```

polkitd aborts every time (reproduced twice, once from a Qt application via polkit-qt `UnixSessionSubject`, once with the busctl call above); systemd restarts it (`NRestarts` increments). Repeating it quickly would presumably hit the unit's start rate limit and leave the system without polkitd — not tested.

Stack (symbols via debuginfod, BuildID `9c47ca3662a847cbef746a72ce325bb1b014e879`):

```
#4  g_assertion_message_expr (libglib-2.0.so.0)
#5  push_subject                                   polkitbackendduktapeauthority.c (g_assert_not_reached)
#6  polkit_backend_common_js_authority_check_authorization_sync   polkitbackendduktapeauthority.c:1022
#7  check_authorization_sync                       polkitbackendinteractiveauthority.c:1500
#8  polkit_backend_interactive_authority_check_authorization   polkitbackendinteractiveauthority.c:1097
#9  server_handle_method_call                      polkitbackendauthority.c:237
```

So `push_subject()` is reachable with a `unix-session` subject as soon as the session ID resolves to a uid, which is the normal case on a logind system. A fix would be to either resolve a `PolkitUnixSession` to a process/uid for the JS `Subject` object, or return an error instead of `g_assert_not_reached()`.
