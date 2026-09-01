#include <libssh/libssh.h>

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

struct SessionDeleter {
  void operator()(ssh_session_struct *session) const noexcept {
    if (session != nullptr) {
      ssh_disconnect(session);
      ssh_free(session);
    }
  }
};
using Session = std::unique_ptr<ssh_session_struct, SessionDeleter>;

struct ChannelDeleter {
  void operator()(ssh_channel_struct *channel) const noexcept {
    if (channel != nullptr) {
      ssh_channel_free(channel);
    }
  }
};
using Channel = std::unique_ptr<ssh_channel_struct, ChannelDeleter>;

[[noreturn]] void fail(ssh_session session, std::string_view operation) {
  throw std::runtime_error(
      std::string(operation) + ": " +
      (session == nullptr ? "no session" : ssh_get_error(session)));
}

void require_ok(int result, ssh_session session, std::string_view operation) {
  if (result != SSH_OK) {
    fail(session, operation);
  }
}

[[nodiscard]] Session connect_session(unsigned int port, const char *identity) {
  Session session(ssh_new());
  if (!session) {
    fail(nullptr, "ssh_new");
  }

  constexpr auto host = "127.0.0.1";
  constexpr auto user = "tester";
  constexpr long timeout = 5;
  require_ok(ssh_options_set(session.get(), SSH_OPTIONS_HOST, host),
             session.get(), "set host");
  require_ok(ssh_options_set(session.get(), SSH_OPTIONS_PORT, &port),
             session.get(), "set port");
  require_ok(ssh_options_set(session.get(), SSH_OPTIONS_USER, user),
             session.get(), "set user");
  require_ok(ssh_options_set(session.get(), SSH_OPTIONS_IDENTITY, identity),
             session.get(), "set identity");
  require_ok(ssh_options_set(session.get(), SSH_OPTIONS_TIMEOUT, &timeout),
             session.get(), "set timeout");
  require_ok(ssh_connect(session.get()), session.get(), "connect");
  require_ok(ssh_userauth_publickey_auto(session.get(), nullptr, nullptr),
             session.get(), "authenticate");
  return session;
}

[[nodiscard]] Channel open_channel(ssh_session session) {
  Channel channel(ssh_channel_new(session));
  if (!channel) {
    fail(session, "create channel");
  }
  require_ok(ssh_channel_open_session(channel.get()), session,
             "open session channel");
  return channel;
}

[[nodiscard]] std::string read_stream(ssh_session session, ssh_channel channel,
                                      int stream) {
  std::string output;
  char buffer[4096];
  for (;;) {
    const auto count = ssh_channel_read_timeout(
        channel, buffer, static_cast<std::uint32_t>(sizeof(buffer)), stream,
        5000);
    if (count == SSH_ERROR) {
      fail(session, "read channel");
    }
    if (count == 0) {
      return output;
    }
    output.append(buffer, static_cast<std::size_t>(count));
  }
}

void require_contains(const std::string &output, std::string_view expected) {
  if (!output.contains(expected)) {
    throw std::runtime_error("missing expected channel output: " +
                             std::string(expected));
  }
}

void require_exit_status(ssh_channel channel, int expected) {
  std::uint32_t status{};
  if (ssh_channel_get_exit_state(channel, &status, nullptr, nullptr) !=
      SSH_OK) {
    throw std::runtime_error("channel did not report an exit status");
  }
  if (status != static_cast<std::uint32_t>(expected)) {
    throw std::runtime_error("unexpected channel exit status: " +
                             std::to_string(status));
  }
}

void exercise_refusal(ssh_session session, ssh_channel channel,
                      std::string_view expected) {
  const auto error = read_stream(session, channel, 1);
  require_contains(error, expected);
  require_exit_status(channel, 126);
}

void exercise_shell_exit(ssh_session session, ssh_channel channel) {
  require_ok(ssh_channel_request_pty_size(channel, "xterm-256color", 80, 24),
             session, "request PTY");
  require_ok(ssh_channel_request_shell(channel), session, "request shell");

  std::string output;
  char buffer[4096];
  while (!output.contains("Signed in as tester")) {
    const auto count = ssh_channel_read_timeout(
        channel, buffer, static_cast<std::uint32_t>(sizeof(buffer)), 0, 5000);
    if (count <= 0) {
      fail(session, "read shell banner");
    }
    output.append(buffer, static_cast<std::size_t>(count));
  }

  constexpr char escape = '\x1b';
  if (ssh_channel_write(channel, &escape, 1U) != 1) {
    fail(session, "write shell exit");
  }
  static_cast<void>(read_stream(session, channel, 0));
  require_exit_status(channel, 0);
}

void exercise(std::string_view mode, ssh_session session, ssh_channel channel) {
  if (mode == "open-close") {
    require_ok(ssh_channel_close(channel), session, "close partial channel");
    return;
  }
  if (mode == "shell-before-pty") {
    require_ok(ssh_channel_request_shell(channel), session, "request shell");
    exercise_refusal(session, channel, "requires an interactive PTY");
    return;
  }
  if (mode == "pty-exec") {
    require_ok(ssh_channel_request_pty_size(channel, "xterm", 80, 24), session,
               "request PTY");
    require_ok(ssh_channel_request_exec(channel, "forbidden-command"), session,
               "request exec");
    exercise_refusal(session, channel, "does not execute commands");
    return;
  }
  if (mode == "pty-subsystem") {
    require_ok(ssh_channel_request_pty_size(channel, "xterm", 80, 24), session,
               "request PTY");
    require_ok(ssh_channel_request_subsystem(channel, "sftp"), session,
               "request subsystem");
    exercise_refusal(session, channel, "does not provide SSH subsystems");
    return;
  }
  if (mode == "second-operation") {
    require_ok(ssh_channel_request_exec(channel, "forbidden-command"), session,
               "request exec");
    if (ssh_channel_request_shell(channel) == SSH_OK) {
      throw std::runtime_error("second operation request was accepted");
    }
    exercise_refusal(session, channel, "does not execute commands");
    return;
  }
  if (mode == "shell-exit") {
    exercise_shell_exit(session, channel);
    return;
  }
  throw std::runtime_error("unknown mode: " + std::string(mode));
}

} // namespace

int main(int argc, char **argv) {
  try {
    if (argc != 4) {
      throw std::runtime_error(
          "usage: anvil_ssh_protocol_client MODE PORT IDENTITY");
    }
    const auto parsed_port = std::stoul(argv[2]);
    if (parsed_port == 0U || parsed_port > 65535U) {
      throw std::runtime_error("invalid port");
    }
    const auto port = static_cast<unsigned int>(parsed_port);
    auto session = connect_session(port, argv[3]);
    auto channel = open_channel(session.get());
    exercise(argv[1], session.get(), channel.get());
    return EXIT_SUCCESS;
  } catch (const std::exception &error) {
    std::cerr << "anvil protocol client: " << error.what() << '\n';
    return EXIT_FAILURE;
  }
}
