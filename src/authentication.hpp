#pragma once

#include <libssh/libssh.h>

#include <anvil/store.hpp>
#include <expected>
#include <string>

namespace anvil::server {

enum class IdentityKind {
  guest,
  registration,
  pending,
  active,
};

struct PublicKeyMaterial {
  std::string fingerprint;
  std::string public_key;

  [[nodiscard]] auto operator==(const PublicKeyMaterial &) const
      -> bool = default;
};

struct SessionIdentity {
  IdentityKind kind{IdentityKind::guest};
  std::string handle;
  PublicKeyMaterial key;

  [[nodiscard]] auto can_write() const noexcept -> bool {
    return kind == IdentityKind::active;
  }

  [[nodiscard]] auto operator==(const SessionIdentity &) const
      -> bool = default;
};

enum class AuthenticationError {
  denied,
  unavailable,
  invalid_key,
  conflict,
};

[[nodiscard]] auto canonical_public_key(ssh_key key)
    -> std::expected<PublicKeyMaterial, AuthenticationError>;
[[nodiscard]] auto resolve_public_key(store::Store &store,
                                      const PublicKeyMaterial &key)
    -> std::expected<SessionIdentity, AuthenticationError>;
[[nodiscard]] auto
provision_pending_identity(store::Store &store, const SessionIdentity &identity,
                           std::string handle, store::UtcEpochSeconds now)
    -> std::expected<SessionIdentity, AuthenticationError>;
[[nodiscard]] auto bootstrap_active_identity(store::Store &store,
                                             std::string handle,
                                             const PublicKeyMaterial &key,
                                             store::UtcEpochSeconds now)
    -> std::expected<void, AuthenticationError>;

}  // namespace anvil::server
