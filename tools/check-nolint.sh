#!/usr/bin/env bash
set -euo pipefail

if (($# != 0)); then
  echo "usage: tools/check-nolint.sh" >&2
  exit 2
fi

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

mapfile -d '' files < <(
  git ls-files -z -- '*.c' '*.cc' '*.cpp' '*.cxx' '*.h' '*.hh' '*.hpp' '*.hxx'
)

if ((${#files[@]} == 0)); then
  echo "error: no tracked C or C++ files found" >&2
  exit 1
fi

perl - "${files[@]}" <<'PERL'
use strict;
use warnings;

my $failed = 0;

while (<>) {
  next unless /\bNOLINT/;

  my $file = $ARGV;
  my $line = $.;
  my $copy = $_;

  if ($copy =~ /\bNOLINT(?:BEGIN|END)\b/) {
    print STDERR "$file:$line: block-wide NOLINT is forbidden; suppress the exact diagnostic\n";
    $failed = 1;
    next;
  }

  my $matched = 0;
  while ($copy =~ s/\bNOLINT(?:NEXTLINE)?\(([^()]*)\)\s+--\s+(\S.{11,})//) {
    my ($list, $reason) = ($1, $2);
    my @checks = split /\s*,\s*/, $list, -1;

    if (!@checks || grep { $_ !~ /\A[A-Za-z0-9][A-Za-z0-9_.-]*-[A-Za-z0-9_.-]+\z/ || /\*/ } @checks) {
      print STDERR "$file:$line: NOLINT must name one or more exact clang-tidy checks\n";
      $failed = 1;
    }

    if ($reason =~ /^\s*$/) {
      print STDERR "$file:$line: NOLINT requires a meaningful justification\n";
      $failed = 1;
    }
    ++$matched;
  }

  if (!$matched || $copy =~ /\bNOLINT/) {
    print STDERR "$file:$line: use NOLINT(check) or NOLINTNEXTLINE(check) followed by ' -- justification'\n";
    $failed = 1;
  }
} continue {
  close ARGV if eof;
}

exit($failed ? 1 : 0);
PERL
