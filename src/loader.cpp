#include <anvil/loader.hpp>

#include <dlfcn.h>
#include <link.h>

#include <algorithm>
#include <sstream>
#include <utility>

namespace anvil::loader {
namespace {

[[nodiscard]] auto mismatch(const char *field, std::uint64_t expected,
                            std::uint64_t found)
    -> std::expected<void, std::string> {
  std::ostringstream message;
  message << field << ": expected " << expected << ", found " << found;
  return std::unexpected(message.str());
}

[[nodiscard]] auto version_text(InterfaceVersion version) -> std::string {
  return std::to_string(version.major) + "." + std::to_string(version.minor);
}

[[nodiscard]] auto
accepted_versions_text(std::span<const InterfaceVersionRange> accepted)
    -> std::string {
  std::ostringstream out;
  for (std::size_t index{}; index < accepted.size(); ++index) {
    if (index != 0)
      out << ", ";
    out << version_text(accepted[index].minimum);
    if (accepted[index].minimum.major != accepted[index].maximum.major ||
        accepted[index].minimum.minor != accepted[index].maximum.minor) {
      out << '-' << version_text(accepted[index].maximum);
    }
  }
  return out.str();
}

[[nodiscard]] auto valid_symbol_name(const std::string &symbol) -> bool {
  return !symbol.empty() && symbol.find('\0') == std::string::npos;
}

[[nodiscard]] auto code_name(ErrorCode code) -> const char * {
  switch (code) {
  case ErrorCode::invalid_request:
    return "invalid request";
  case ErrorCode::open_failed:
    return "open failed";
  case ErrorCode::symbol_missing:
    return "symbol missing";
  case ErrorCode::symbol_null:
    return "symbol null";
  case ErrorCode::abi_rejected:
    return "ABI rejected";
  case ErrorCode::factory_returned_null:
    return "factory returned null";
  }
  return "unknown loader error";
}

} // namespace

auto supports_interface_version(
    InterfaceVersion version,
    std::span<const InterfaceVersionRange> accepted) noexcept -> bool {
  return std::ranges::any_of(accepted, [version](const auto &range) {
    return range.minimum.major == range.maximum.major &&
           version.major == range.minimum.major &&
           range.minimum.minor <= range.maximum.minor &&
           version.minor >= range.minimum.minor &&
           version.minor <= range.maximum.minor;
  });
}

auto verify_abi_tag(const AnvilAbiTag &expected, const AnvilAbiTag &found,
                    std::size_t readable_size)
    -> std::expected<void, std::string> {
  if (readable_size < kAbiTagPrefixSize) {
    return mismatch("storage_size", kAbiTagPrefixSize, readable_size);
  }
  if (found.magic != expected.magic)
    return mismatch("magic", expected.magic, found.magic);
  if (found.struct_size < kAbiTagPrefixSize) {
    return mismatch("struct_size", kAbiTagPrefixSize, found.struct_size);
  }
  if (found.struct_size > readable_size) {
    return std::unexpected(
        "struct_size: declared " + std::to_string(found.struct_size) +
        " bytes, readable storage contains " + std::to_string(readable_size));
  }
  if (!abi_tag_field_available(found, readable_size,
                               __builtin_offsetof(AnvilAbiTag, sanitizer_mask),
                               sizeof(found.sanitizer_mask))) {
    return std::unexpected("sanitizer_mask: field is not present");
  }

  const auto found_version =
      InterfaceVersion{found.interface_major, found.interface_minor};
  if (!supports_interface_version(found_version,
                                  kAcceptedPluginInterfaceVersions)) {
    return std::unexpected(
        "interface_version: accepted " +
        accepted_versions_text(kAcceptedPluginInterfaceVersions) + ", found " +
        version_text(found_version));
  }
  if (found.sanitizer_mask != expected.sanitizer_mask) {
    return mismatch("sanitizer_mask", expected.sanitizer_mask,
                    found.sanitizer_mask);
  }
  return {};
}

auto Error::message() const -> std::string {
  std::ostringstream out;
  out << plugin.string() << ": " << code_name(code);
  if (!symbol.empty())
    out << " [" << symbol << ']';
  if (!detail.empty())
    out << ": " << detail;
  return out.str();
}

auto detail::open_library(const std::filesystem::path &plugin)
    -> std::expected<Handle, Error> {
  ::dlerror();
  void *raw = ::dlopen(plugin.c_str(), RTLD_NOW | RTLD_LOCAL);
  if (raw == nullptr) {
    const char *message = ::dlerror();
    return std::unexpected(
        Error{ErrorCode::open_failed,
              plugin,
              {},
              message == nullptr ? "dlopen failed" : message});
  }

  return Handle{raw, [](void *value) noexcept {
                  if (value != nullptr)
                    static_cast<void>(::dlclose(value));
                }};
}

auto detail::find_symbol(const Handle &handle,
                         const std::filesystem::path &plugin,
                         const std::string &symbol)
    -> std::expected<void *, Error> {
  if (!valid_symbol_name(symbol)) {
    return std::unexpected(
        Error{ErrorCode::invalid_request, plugin, symbol,
              "a symbol name must be non-empty and contain no NUL"});
  }

  ::dlerror();
  void *address = ::dlsym(handle.get(), symbol.c_str());
  const char *message = ::dlerror();
  if (message != nullptr) {
    return std::unexpected(
        Error{ErrorCode::symbol_missing, plugin, symbol, message});
  }
  return address;
}

auto detail::symbol_storage_size(void *address,
                                 const std::filesystem::path &plugin,
                                 const std::string &symbol)
    -> std::expected<std::size_t, Error> {
  Dl_info info{};
  void *extra = nullptr;
  if (::dladdr1(address, &info, &extra, RTLD_DL_SYMENT) == 0 ||
      extra == nullptr) {
    return std::unexpected(Error{
        ErrorCode::abi_rejected, plugin, symbol,
        "the dynamic loader could not determine the ABI tag's storage size"});
  }

  const auto *elf_symbol = static_cast<const ElfW(Sym) *>(extra);
  return static_cast<std::size_t>(elf_symbol->st_size);
}

} // namespace anvil::loader
