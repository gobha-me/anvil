#include <anvil/loader.hpp>

#include <dlfcn.h>
#include <link.h>

#include <sstream>
#include <utility>

namespace anvil::loader {
namespace {

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
