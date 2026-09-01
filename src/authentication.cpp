#include "authentication.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <limits>
#include <memory>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <utility>

#include "server.hpp"

namespace anvil::server {
namespace {

struct HashDeleter {
  void operator()(unsigned char *hash) const noexcept {
    if (hash != nullptr) {
      ssh_clean_pubkey_hash(&hash);
    }
  }
};

struct StringDeleter {
  void operator()(char *value) const noexcept {
    if (value != nullptr) {
      ssh_string_free_char(value);
    }
  }
};

[[nodiscard]] auto authentication_error(const store::Error &error)
    -> AuthenticationError {
  switch (error.code) {
  case store::ErrorCode::conflict:
  case store::ErrorCode::constraint_violation:
    return AuthenticationError::conflict;
  case store::ErrorCode::invalid_data:
    return AuthenticationError::invalid_key;
  case store::ErrorCode::unavailable:
  case store::ErrorCode::not_found:
  case store::ErrorCode::invalid_state:
  case store::ErrorCode::internal:
    return AuthenticationError::unavailable;
  }
  return AuthenticationError::unavailable;
}

} // namespace

auto hash_invite_code(std::string_view code)
    -> std::expected<std::string, AuthenticationError> {
  constexpr std::size_t max_invite_code_size = 256;
  if (code.empty() || code.size() > max_invite_code_size) {
    return std::unexpected(AuthenticationError::invite_unavailable);
  }
  for (const auto character : code) {
    const auto byte = static_cast<unsigned char>(character);
    if (byte < 0x21U || byte > 0x7EU) {
      return std::unexpected(AuthenticationError::invite_unavailable);
    }
  }

  std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
  unsigned int digest_size = 0;
  if (EVP_Digest(code.data(), code.size(), digest.data(), &digest_size,
                 EVP_sha256(), nullptr) != 1 ||
      digest_size != 32U) {
    return std::unexpected(AuthenticationError::unavailable);
  }
  constexpr std::string_view hexadecimal = "0123456789abcdef";
  std::string result;
  result.reserve(64);
  for (std::size_t index = 0; index < digest_size; ++index) {
    const auto byte = digest[index];
    result.push_back(hexadecimal[byte >> 4U]);
    result.push_back(hexadecimal[byte & 0x0FU]);
  }
  return result;
}

auto issue_invite_code(store::Store &store, std::string_view inviter_handle,
                       store::UtcEpochSeconds now, const InvitePolicy &policy)
    -> std::expected<IssuedInvite, AuthenticationError> {
  constexpr std::size_t raw_size = 24;
  constexpr std::size_t encoded_size = 32;
  constexpr unsigned int collision_attempts = 3;
  if (inviter_handle.empty() || policy.per_user > 1'000'000U ||
      policy.regeneration.count() <= 0 || policy.expiration.count() <= 0 ||
      policy.regeneration.count() > std::numeric_limits<std::uint32_t>::max() ||
      policy.expiration.count() >
          std::numeric_limits<std::int64_t>::max() - now.value) {
    return std::unexpected(AuthenticationError::unavailable);
  }
  const auto expires_at = store::UtcEpochSeconds{
      now.value + static_cast<std::int64_t>(policy.expiration.count())};
  for (unsigned int attempt = 0; attempt < collision_attempts; ++attempt) {
    std::array<unsigned char, raw_size> raw{};
    if (RAND_priv_bytes(raw.data(), static_cast<int>(raw.size())) != 1) {
      return std::unexpected(AuthenticationError::unavailable);
    }
    std::array<unsigned char, encoded_size + 1> encoded{};
    const auto count = EVP_EncodeBlock(encoded.data(), raw.data(),
                                       static_cast<int>(raw.size()));
    if (count != static_cast<int>(encoded_size)) {
      return std::unexpected(AuthenticationError::unavailable);
    }
    std::string code(reinterpret_cast<const char *>(encoded.data()),
                     encoded_size);
    std::ranges::replace(code, '+', '-');
    std::ranges::replace(code, '/', '_');
    auto hash = hash_invite_code(code);
    if (!hash) {
      return std::unexpected(hash.error());
    }
    auto transaction = store.begin(store::TransactionMode::read_write);
    if (!transaction) {
      return std::unexpected(authentication_error(transaction.error()));
    }
    auto issued = store.issue_invite(
        *transaction, store::InviteIssue{
                          .code_hash = std::move(*hash),
                          .inviter_handle = std::string(inviter_handle),
                          .created_at = now,
                          .expires_at = expires_at,
                          .balance_cap = policy.per_user,
                          .regeneration_seconds = static_cast<std::uint32_t>(
                              policy.regeneration.count()),
                      });
    if (!issued) {
      if (issued.error().code == store::ErrorCode::conflict) {
        continue;
      }
      return std::unexpected(authentication_error(issued.error()));
    }
    if (auto committed = transaction->commit(); !committed) {
      return std::unexpected(authentication_error(committed.error()));
    }
    return IssuedInvite{.code = std::move(code),
                        .expires_at = expires_at,
                        .remaining_balance = issued->remaining_balance};
  }
  return std::unexpected(AuthenticationError::conflict);
}

auto canonical_public_key(ssh_key key)
    -> std::expected<PublicKeyMaterial, AuthenticationError> {
  if (key == nullptr) {
    return std::unexpected(AuthenticationError::invalid_key);
  }
  unsigned char *raw_hash = nullptr;
  std::size_t hash_size = 0;
  if (ssh_get_publickey_hash(key, SSH_PUBLICKEY_HASH_SHA256, &raw_hash,
                             &hash_size) != SSH_OK ||
      raw_hash == nullptr || hash_size == 0) {
    if (raw_hash != nullptr) {
      ssh_clean_pubkey_hash(&raw_hash);
    }
    return std::unexpected(AuthenticationError::invalid_key);
  }
  std::unique_ptr<unsigned char, HashDeleter> hash(raw_hash);
  std::unique_ptr<char, StringDeleter> fingerprint(ssh_get_fingerprint_hash(
      SSH_PUBLICKEY_HASH_SHA256, hash.get(), hash_size));
  char *raw_encoded = nullptr;
  if (!fingerprint ||
      ssh_pki_export_pubkey_base64(key, &raw_encoded) != SSH_OK ||
      raw_encoded == nullptr) {
    if (raw_encoded != nullptr) {
      ssh_string_free_char(raw_encoded);
    }
    return std::unexpected(AuthenticationError::invalid_key);
  }
  std::unique_ptr<char, StringDeleter> encoded(raw_encoded);
  const auto *type = ssh_key_type_to_char(ssh_key_type(key));
  if (type == nullptr || *type == '\0' || *fingerprint == '\0' ||
      *encoded == '\0') {
    return std::unexpected(AuthenticationError::invalid_key);
  }
  return PublicKeyMaterial{
      .fingerprint = std::string(fingerprint.get()),
      .public_key = std::string(type) + ' ' + encoded.get(),
  };
}

auto resolve_public_key(store::Store &store, const PublicKeyMaterial &key,
                        std::string_view tos_version)
    -> std::expected<SessionIdentity, AuthenticationError> {
  auto transaction = store.begin(store::TransactionMode::read_only);
  if (!transaction) {
    return std::unexpected(authentication_error(transaction.error()));
  }
  auto record = store.find_local_credential(*transaction, key.fingerprint);
  if (!record) {
    return std::unexpected(authentication_error(record.error()));
  }
  std::optional<bool> accepted;
  if (record->has_value() &&
      (*record)->status == store::CredentialStatus::active) {
    auto current =
        store.has_tos_acceptance(*transaction, (*record)->handle, tos_version);
    if (!current) {
      return std::unexpected(authentication_error(current.error()));
    }
    accepted = *current;
  }
  if (auto committed = transaction->commit(); !committed) {
    return std::unexpected(authentication_error(committed.error()));
  }
  if (!record->has_value()) {
    return SessionIdentity{
        .kind = IdentityKind::registration, .handle = {}, .key = key};
  }
  if ((*record)->public_key != key.public_key) {
    return std::unexpected(AuthenticationError::denied);
  }
  if ((*record)->status == store::CredentialStatus::pending) {
    return SessionIdentity{
        .kind = IdentityKind::pending, .handle = (*record)->handle, .key = key};
  }
  if ((*record)->status == store::CredentialStatus::active) {
    return SessionIdentity{.kind = *accepted ? IdentityKind::active
                                             : IdentityKind::tos_required,
                           .handle = (*record)->handle,
                           .key = key};
  }
  return std::unexpected(AuthenticationError::denied);
}

auto accept_current_tos(store::Store &store, const SessionIdentity &identity,
                        std::string_view tos_version,
                        store::UtcEpochSeconds now)
    -> std::expected<SessionIdentity, AuthenticationError> {
  if ((identity.kind != IdentityKind::pending &&
       identity.kind != IdentityKind::tos_required) ||
      identity.handle.empty()) {
    return std::unexpected(AuthenticationError::denied);
  }
  auto transaction = store.begin(store::TransactionMode::read_write);
  if (!transaction) {
    return std::unexpected(authentication_error(transaction.error()));
  }
  auto accepted = store.accept_tos(
      *transaction,
      store::TosAcceptance{.user_handle = identity.handle,
                           .tos_version = std::string(tos_version),
                           .accepted_at = now});
  if (!accepted || *accepted != store::UserStatus::active) {
    return std::unexpected(accepted ? AuthenticationError::unavailable
                                    : authentication_error(accepted.error()));
  }
  if (auto committed = transaction->commit(); !committed) {
    return std::unexpected(authentication_error(committed.error()));
  }
  auto result = identity;
  result.kind = IdentityKind::active;
  return result;
}

auto provision_pending_identity(store::Store &store,
                                const SessionIdentity &identity,
                                std::string handle, store::UtcEpochSeconds now,
                                std::optional<std::string_view> invite_code)
    -> std::expected<SessionIdentity, AuthenticationError> {
  if (identity.kind != IdentityKind::registration ||
      identity.key.fingerprint.empty() || identity.key.public_key.empty()) {
    return std::unexpected(AuthenticationError::denied);
  }
  std::optional<std::string> invite_hash;
  if (invite_code) {
    auto hashed = hash_invite_code(*invite_code);
    if (!hashed) {
      return std::unexpected(hashed.error());
    }
    invite_hash = std::move(*hashed);
  }
  auto transaction = store.begin(store::TransactionMode::read_write);
  if (!transaction) {
    return std::unexpected(authentication_error(transaction.error()));
  }
  const auto provisioned = store.provision_local_credential(
      *transaction, store::LocalCredentialProvision{
                        .handle = handle,
                        .fingerprint = identity.key.fingerprint,
                        .public_key = identity.key.public_key,
                        .created_at = now,
                        .user_status = store::UserStatus::pending,
                    });
  if (!provisioned) {
    return std::unexpected(authentication_error(provisioned.error()));
  }
  if (invite_hash) {
    const auto claimed = store.claim_invite(
        *transaction, store::InviteClaim{.code_hash = *invite_hash,
                                         .claimed_by_handle = handle,
                                         .claimed_at = now});
    if (!claimed) {
      return std::unexpected(claimed.error().code == store::ErrorCode::conflict
                                 ? AuthenticationError::invite_unavailable
                                 : authentication_error(claimed.error()));
    }
  }
  if (auto committed = transaction->commit(); !committed) {
    return std::unexpected(authentication_error(committed.error()));
  }
  return SessionIdentity{.kind = IdentityKind::pending,
                         .handle = std::move(handle),
                         .key = identity.key};
}

auto bootstrap_active_identity(store::Store &store, std::string handle,
                               const PublicKeyMaterial &key,
                               store::UtcEpochSeconds now)
    -> std::expected<void, AuthenticationError> {
  auto transaction = store.begin(store::TransactionMode::read_write);
  if (!transaction) {
    return std::unexpected(authentication_error(transaction.error()));
  }
  const auto provisioned = store.provision_local_credential(
      *transaction, store::LocalCredentialProvision{
                        .handle = std::move(handle),
                        .fingerprint = key.fingerprint,
                        .public_key = key.public_key,
                        .created_at = now,
                        .user_status = store::UserStatus::active,
                    });
  if (!provisioned) {
    return std::unexpected(authentication_error(provisioned.error()));
  }
  if (auto committed = transaction->commit(); !committed) {
    return std::unexpected(authentication_error(committed.error()));
  }
  return {};
}

} // namespace anvil::server
