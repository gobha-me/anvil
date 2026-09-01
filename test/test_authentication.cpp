#include <catch2/catch_test_macros.hpp>

#include "authentication.hpp"
#include "server.hpp"
#include "support/memory_store.hpp"

namespace {

using anvil::server::AuthenticationError;
using anvil::server::IdentityKind;
using anvil::server::PublicKeyMaterial;
using anvil::server::SessionIdentity;

const PublicKeyMaterial alice_key{"SHA256:alice", "ssh-ed25519 ALICE"};
constexpr std::string_view invite_code = "invite-123";
constexpr std::string_view invite_hash =
    "fbaf7ba4264e2392988d8b5863e0a080bfe65b2a48d9b9f042f7cc7d4f711bb9";

} // namespace

TEST_CASE("unknown, pending, TOS-gated, and active keys resolve explicitly") {
  anvil::testing::MemoryStore store;
  auto unknown = anvil::server::resolve_public_key(store, alice_key, "v1");
  REQUIRE(unknown.has_value());
  CHECK(unknown->kind == IdentityKind::registration);
  CHECK_FALSE(unknown->can_write());

  auto pending = anvil::server::provision_pending_identity(
      store, *unknown, "alice", anvil::store::UtcEpochSeconds{10});
  REQUIRE(pending.has_value());
  CHECK(pending->kind == IdentityKind::pending);
  CHECK_FALSE(pending->can_write());
  auto resolved_pending =
      anvil::server::resolve_public_key(store, alice_key, "v1");
  REQUIRE(resolved_pending.has_value());
  CHECK(resolved_pending->kind == IdentityKind::pending);

  const PublicKeyMaterial operator_key{"SHA256:operator",
                                       "ssh-ed25519 OPERATOR"};
  REQUIRE(
      anvil::server::bootstrap_active_identity(
          store, "operator", operator_key, anvil::store::UtcEpochSeconds{11})
          .has_value());
  auto gated = anvil::server::resolve_public_key(store, operator_key, "v1");
  REQUIRE(gated.has_value());
  CHECK(gated->kind == IdentityKind::tos_required);
  CHECK(gated->handle == "operator");
  CHECK(gated->can_read());
  CHECK_FALSE(gated->can_write());
  auto accepted = anvil::server::accept_current_tos(
      store, *gated, "v1", anvil::store::UtcEpochSeconds{12});
  REQUIRE(accepted.has_value());
  CHECK(accepted->kind == IdentityKind::active);
  CHECK(accepted->can_write());
  auto active = anvil::server::resolve_public_key(store, operator_key, "v1");
  REQUIRE(active.has_value());
  CHECK(active->kind == IdentityKind::active);
}

TEST_CASE("invite codes are bounded opaque tokens with stable SHA256 hashes") {
  CHECK(anvil::server::hash_invite_code(invite_code) == invite_hash);
  CHECK_FALSE(anvil::server::hash_invite_code("").has_value());
  CHECK_FALSE(anvil::server::hash_invite_code("contains space").has_value());
  CHECK_FALSE(
      anvil::server::hash_invite_code(std::string(257, 'x')).has_value());
}

TEST_CASE(
    "issued invite codes are random URL-safe bearer tokens stored by hash") {
  anvil::testing::MemoryStore store;
  const PublicKeyMaterial operator_key{"SHA256:operator",
                                       "ssh-ed25519 OPERATOR"};
  REQUIRE(anvil::server::bootstrap_active_identity(
              store, "operator", operator_key, anvil::store::UtcEpochSeconds{1})
              .has_value());
  const anvil::server::InvitePolicy policy{
      .per_user = 1,
      .regeneration = std::chrono::seconds(100),
      .expiration = std::chrono::seconds(7),
      .notify_inviters_on_moderation = false};
  const auto issued = anvil::server::issue_invite_code(
      store, "operator", anvil::store::UtcEpochSeconds{10}, policy);
  REQUIRE(issued.has_value());
  CHECK(issued->code.size() == 32);
  CHECK(
      issued->code.find_first_not_of(
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") ==
      std::string::npos);
  CHECK(issued->expires_at == anvil::store::UtcEpochSeconds{17});
  CHECK(issued->remaining_balance == 0);

  const PublicKeyMaterial invited_key{"SHA256:invited", "ssh-ed25519 INVITED"};
  const SessionIdentity registration{
      .kind = IdentityKind::registration, .handle = {}, .key = invited_key};
  REQUIRE(anvil::server::provision_pending_identity(
              store, registration, "invited", anvil::store::UtcEpochSeconds{16},
              issued->code)
              .has_value());
  CHECK_FALSE(anvil::server::issue_invite_code(
                  store, "operator", anvil::store::UtcEpochSeconds{17}, policy)
                  .has_value());
}

TEST_CASE("invite registration claims once and rolls back the losing account") {
  anvil::testing::MemoryStore store;
  store.seed_invite(std::string(invite_hash));
  const SessionIdentity first{
      .kind = IdentityKind::registration, .handle = {}, .key = alice_key};
  auto registered = anvil::server::provision_pending_identity(
      store, first, "alice", anvil::store::UtcEpochSeconds{10}, invite_code);
  REQUIRE(registered.has_value());
  CHECK(store.invite_claimant(invite_hash) == "alice");

  const PublicKeyMaterial bob_key{"SHA256:bob", "ssh-ed25519 BOB"};
  const SessionIdentity second{
      .kind = IdentityKind::registration, .handle = {}, .key = bob_key};
  const auto refused = anvil::server::provision_pending_identity(
      store, second, "bob", anvil::store::UtcEpochSeconds{11}, invite_code);
  REQUIRE_FALSE(refused.has_value());
  CHECK(refused.error() == AuthenticationError::invite_unavailable);
  CHECK(store.invite_claimant(invite_hash) == "alice");
  const auto unresolved =
      anvil::server::resolve_public_key(store, bob_key, "v1");
  REQUIRE(unresolved.has_value());
  CHECK(unresolved->kind == IdentityKind::registration);
}

TEST_CASE("revoked and mismatched credentials fail closed") {
  anvil::testing::MemoryStore store;
  store.seed_credential(anvil::store::CredentialRecord{
      .handle = "alice",
      .fingerprint = alice_key.fingerprint,
      .public_key = alice_key.public_key,
      .status = anvil::store::CredentialStatus::revoked,
  });
  const auto revoked =
      anvil::server::resolve_public_key(store, alice_key, "v1");
  REQUIRE_FALSE(revoked.has_value());
  CHECK(revoked.error() == AuthenticationError::denied);

  store.seed_credential(anvil::store::CredentialRecord{
      .handle = "alice",
      .fingerprint = "SHA256:collision",
      .public_key = "ssh-ed25519 STORED",
      .status = anvil::store::CredentialStatus::active,
  });
  const auto mismatched = anvil::server::resolve_public_key(
      store, {"SHA256:collision", "ssh-ed25519 OFFERED"}, "v1");
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
