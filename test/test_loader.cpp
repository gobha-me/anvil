#include <anvil/loader.hpp>

#include "fixtures/plugin_api.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cerrno>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <system_error>

#include <unistd.h>

TestPlugin::~TestPlugin() = default;

namespace {

using anvil::loader::AbiRequirement;
using anvil::loader::ErrorCode;

inline constexpr AbiRequirement<anvil::AnvilAbiTag> kRequirement{
    anvil::current_abi_tag, anvil::loader::verify_abi_tag};

class EventFile {
public:
  EventFile()
      : path_{std::filesystem::temp_directory_path() /
              ("anvil-loader-" + std::to_string(::getpid()) + "-" +
               std::to_string(next_id_++) + ".log")} {
    std::error_code error;
    std::filesystem::remove(path_, error);
    if (::setenv("ANVIL_LOADER_EVENT_FILE", path_.c_str(), 1) != 0) {
      throw std::system_error{errno, std::generic_category(), "setenv"};
    }
  }

  ~EventFile() {
    static_cast<void>(::unsetenv("ANVIL_LOADER_EVENT_FILE"));
    std::error_code error;
    std::filesystem::remove(path_, error);
  }

  [[nodiscard]] auto contents() const -> std::string {
    std::ifstream in{path_};
    return {std::istreambuf_iterator<char>{in},
            std::istreambuf_iterator<char>{}};
  }

private:
  std::filesystem::path path_;
  inline static unsigned next_id_{};
};

} // namespace

TEST_CASE("a valid plugin loads and can be called") {
  auto loaded =
      anvil::loader::load<TestPlugin>(ANVIL_FIXTURE_valid, kRequirement);

  REQUIRE(loaded.has_value());
  REQUIRE(loaded->handle);
  REQUIRE(loaded->instance);
  CHECK(loaded->instance->value() == 42);
}

TEST_CASE("an ABI mismatch rejects before any exported entrypoint") {
  EventFile events;

  auto loaded =
      anvil::loader::load<TestPlugin>(ANVIL_FIXTURE_mismatched, kRequirement);

  REQUIRE_FALSE(loaded.has_value());
  CHECK(loaded.error().code == ErrorCode::abi_rejected);
  CHECK(loaded.error().symbol == "anvil_abi_tag");
  CHECK(loaded.error().detail.find("interface_major: expected 1, found 2") !=
        std::string::npos);
  CHECK(events.contents() == "initializer\n");
}

TEST_CASE("a sanitizer mismatch is a hard refusal before entrypoint lookup") {
  auto loaded = anvil::loader::load<TestPlugin>(
      ANVIL_FIXTURE_mismatched_sanitizer, kRequirement);

  REQUIRE_FALSE(loaded.has_value());
  CHECK(loaded.error().code == ErrorCode::abi_rejected);
  CHECK(loaded.error().symbol == "anvil_abi_tag");
  CHECK(loaded.error().detail.find("sanitizer_mask: expected ") !=
        std::string::npos);
}

TEST_CASE("a missing ABI tag fails before the factory") {
  EventFile events;

  auto loaded =
      anvil::loader::load<TestPlugin>(ANVIL_FIXTURE_missing_tag, kRequirement);

  REQUIRE_FALSE(loaded.has_value());
  CHECK(loaded.error().code == ErrorCode::symbol_missing);
  CHECK(loaded.error().symbol == "anvil_abi_tag");
  CHECK(loaded.error().message().find(ANVIL_FIXTURE_missing_tag) !=
        std::string::npos);
  CHECK(events.contents().empty());
}

TEST_CASE("missing factory and destroy exports identify the exact symbol") {
  auto missing_factory = anvil::loader::load<TestPlugin>(
      ANVIL_FIXTURE_missing_factory, kRequirement);
  REQUIRE_FALSE(missing_factory.has_value());
  CHECK(missing_factory.error().code == ErrorCode::symbol_missing);
  CHECK(missing_factory.error().symbol == "anvil_plugin_create");
  CHECK_FALSE(missing_factory.error().detail.empty());

  EventFile events;
  auto missing_destroy = anvil::loader::load<TestPlugin>(
      ANVIL_FIXTURE_missing_destroy, kRequirement);
  REQUIRE_FALSE(missing_destroy.has_value());
  CHECK(missing_destroy.error().code == ErrorCode::symbol_missing);
  CHECK(missing_destroy.error().symbol == "anvil_plugin_destroy");
  CHECK(events.contents().empty());
}

TEST_CASE("a null factory result is a named failure") {
  auto loaded =
      anvil::loader::load<TestPlugin>(ANVIL_FIXTURE_null_factory, kRequirement);

  REQUIRE_FALSE(loaded.has_value());
  CHECK(loaded.error().code == ErrorCode::factory_returned_null);
  CHECK(loaded.error().plugin == ANVIL_FIXTURE_null_factory);
  CHECK(loaded.error().symbol == "anvil_plugin_create");
  CHECK_FALSE(loaded.error().detail.empty());
}

TEST_CASE("a resolved address-zero symbol is not reported as missing") {
  auto loaded =
      anvil::loader::load<TestPlugin>(ANVIL_FIXTURE_null_tag, kRequirement);

  REQUIRE_FALSE(loaded.has_value());
  CHECK(loaded.error().code == ErrorCode::symbol_null);
  CHECK(loaded.error().symbol == "anvil_abi_tag");
}

TEST_CASE("a truncated ABI tag is refused before it is copied") {
  auto loaded =
      anvil::loader::load<TestPlugin>(ANVIL_FIXTURE_short_tag, kRequirement);

  REQUIRE_FALSE(loaded.has_value());
  CHECK(loaded.error().code == ErrorCode::abi_rejected);
  CHECK(loaded.error().symbol == "anvil_abi_tag");
  CHECK(loaded.error().detail.find("4 bytes; expected at least 48") !=
        std::string::npos);
}

TEST_CASE("the Anvil verifier gates compatibility fields only") {
  auto found = anvil::current_abi_tag;
  found.compiler = anvil::AbiCompiler::unknown;
  found.compiler_major = 99;
  found.compiler_minor = 98;
  found.compiler_patch = 97;
  found.standard_library = anvil::AbiStandardLibrary::unknown;
  found.standard_library_version = 123;
  found.language_standard = 1;

  CHECK(anvil::loader::verify_abi_tag(anvil::current_abi_tag, found));

  found.magic = 0;
  auto bad_magic = anvil::loader::verify_abi_tag(anvil::current_abi_tag, found);
  REQUIRE_FALSE(bad_magic);
  CHECK(bad_magic.error().find("magic: expected ") != std::string::npos);

  found = anvil::current_abi_tag;
  --found.struct_size;
  auto short_struct =
      anvil::loader::verify_abi_tag(anvil::current_abi_tag, found);
  REQUIRE_FALSE(short_struct);
  CHECK(short_struct.error().find("struct_size: expected 48, found 47") !=
        std::string::npos);

  found = anvil::current_abi_tag;
  ++found.interface_minor;
  auto wrong_minor =
      anvil::loader::verify_abi_tag(anvil::current_abi_tag, found);
  REQUIRE_FALSE(wrong_minor);
  CHECK(wrong_minor.error().find("interface_minor: expected 0, found 1") !=
        std::string::npos);
}

TEST_CASE("the instance keeps its library mapped and destroys before dlclose") {
  EventFile events;
  std::shared_ptr<TestPlugin> instance;

  {
    auto loaded =
        anvil::loader::load<TestPlugin>(ANVIL_FIXTURE_valid, kRequirement);
    REQUIRE(loaded.has_value());

    instance = loaded->instance;
    loaded->handle.reset();
    loaded->instance.reset();
    CHECK(instance->value() == 42);
    CHECK(events.contents().empty());
  }

  instance.reset();
  CHECK(events.contents() == "destroy\nunload\n");
}

TEST_CASE("invalid caller inputs fail without entering the dynamic loader") {
  auto null_verifier = anvil::loader::load<TestPlugin>(
      ANVIL_FIXTURE_valid,
      AbiRequirement<anvil::AnvilAbiTag>{anvil::current_abi_tag, nullptr});
  REQUIRE_FALSE(null_verifier.has_value());
  CHECK(null_verifier.error().code == ErrorCode::invalid_request);

  auto names = anvil::loader::SymbolNames{};
  names.abi_tag.clear();
  auto empty_symbol =
      anvil::loader::load<TestPlugin>(ANVIL_FIXTURE_valid, kRequirement, names);
  REQUIRE_FALSE(empty_symbol.has_value());
  CHECK(empty_symbol.error().code == ErrorCode::invalid_request);
}

TEST_CASE("a missing library reports its path and dlopen diagnostic") {
  const auto missing =
      std::filesystem::path{ANVIL_FIXTURE_valid}.parent_path() /
      "does-not-exist.so";
  auto loaded = anvil::loader::load<TestPlugin>(missing, kRequirement);

  REQUIRE_FALSE(loaded.has_value());
  CHECK(loaded.error().code == ErrorCode::open_failed);
  CHECK(loaded.error().plugin == missing);
  CHECK_FALSE(loaded.error().detail.empty());
}
