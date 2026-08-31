#include <catch2/catch_test_macros.hpp>

#include "authentication.hpp"
#include "support/memory_store.hpp"

namespace {

using anvil::server::AuthenticationError;
using anvil::server::IdentityKind;
using anvil::server::PublicKeyMaterial;
using anvil::server::SessionIdentity;

const PublicKeyMaterial alice_key{"SHA256:alice", "ssh-ed25519 ALICE"};

}  // namespace

TEST_CASE("unknown, pending, and active keys resolve to explicit identities") {
  anvil::testing::MemoryStore store;
  auto unknown = anvil::server::resolve_public_key(store, alice_key);
  REQUIRE(unknown.has_value());
  CHECK(unknown->kind == IdentityKind::registration);
  CHECK_FALSE(unknown->can_write());

  auto pending = anvil::server::provision_pending_identity(
      store, *unknown, "alice", anvil::store::UtcEpochSeconds{10});
  REQUIRE(pending.has_value());
  CHECK(pending->kind == IdentityKind::pending);
  CHECK_FALSE(pending->can_write());
  auto resolved_pending = anvil::server::resolve_public_key(store, alice_key);
  REQUIRE(resolved_pending.has_value());
  CHECK(resolved_pending->kind == IdentityKind::pending);

  const PublicKeyMaterial operator_key{"SHA256:operator",
                                       "ssh-ed25519 OPERATOR"};
  REQUIRE(
      anvil::server::bootstrap_active_identity(
          store, "operator", operator_key, anvil::store::UtcEpochSeconds{11})
          .has_value());
  auto active = anvil::server::resolve_public_key(store, operator_key);
  REQUIRE(active.has_value());
  CHECK(active->kind == IdentityKind::active);
  CHECK(active->handle == "operator");
  CHECK(active->can_write());
}

TEST_CASE("revoked and mismatched credentials fail closed") {
  anvil::testing::MemoryStore store;
  store.seed_credential(anvil::store::CredentialRecord{
      .handle = "alice",
      .fingerprint = alice_key.fingerprint,
      .public_key = alice_key.public_key,
      .status = anvil::store::CredentialStatus::revoked,
  });
  const auto revoked = anvil::server::resolve_public_key(store, alice_key);
  REQUIRE_FALSE(revoked.has_value());
  CHECK(revoked.error() == AuthenticationError::denied);

  store.seed_credential(anvil::store::CredentialRecord{
      .handle = "alice",
      .fingerprint = "SHA256:collision",
      .public_key = "ssh-ed25519 STORED",
      .status = anvil::store::CredentialStatus::active,
  });
  const auto mismatched = anvil::server::resolve_public_key(
      store, {"SHA256:collision", "ssh-ed25519 OFFERED"});
  REQUIRE_FALSE(mismatched.has_value());
  CHECK(mismatched.error() == AuthenticationError::denied);
}

TEST_CASE("only registration identities can create pending accounts") {
  anvil::testing::MemoryStore store;
  const SessionIdentity guest{
      .kind = IdentityKind::guest, .handle = {}, .key = {}};
  const auto refused = anvil::server::provision_pending_identity(
      store, guest, "alice", anvil::store::UtcEpochSeconds{10});
  REQUIRE_FALSE(refused.has_value());
  CHECK(refused.error() == AuthenticationError::denied);

  const SessionIdentity registration{
      .kind = IdentityKind::registration, .handle = {}, .key = alice_key};
  const auto reserved = anvil::server::provision_pending_identity(
      store, registration, "guest", anvil::store::UtcEpochSeconds{10});
  REQUIRE_FALSE(reserved.has_value());
  CHECK(reserved.error() == AuthenticationError::invalid_key);
}
