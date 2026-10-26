#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

mkdir -p "${tmp}/lib/guard" "${tmp}/home"
cp "${script_dir}/xena-agent" "${tmp}/lib/xena-agent"
chmod 755 "${tmp}/lib/xena-agent"

cat >"${tmp}/lib/guard/ok-case.sh" <<'EOF'
#!/usr/bin/env bash
echo "guard ran"
exit 0
EOF

cat >"${tmp}/lib/guard/fail-case.sh" <<'EOF'
#!/usr/bin/env bash
exit 3
EOF

out=""
err=""
code=0

fail() {
  echo "FAIL: $1"
  exit 1
}

run_agent() {
  code=0
  HOME="${tmp}/home" SSH_ORIGINAL_COMMAND="$1" "${tmp}/lib/xena-agent" \
    >"${tmp}/out" 2>"${tmp}/err" || code=$?
  out="$(tr -d '\0' <"${tmp}/out")"
  err="$(cat "${tmp}/err")"
}

run_agent_unset() {
  code=0
  env -u SSH_ORIGINAL_COMMAND HOME="${tmp}/home" "${tmp}/lib/xena-agent" \
    >"${tmp}/out" 2>"${tmp}/err" </dev/null || code=$?
  out="$(tr -d '\0' <"${tmp}/out")"
  err="$(cat "${tmp}/err")"
}

expect_refused() {
  [[ "${code}" == "2" ]] || fail "$1: exit ${code}, want 2"
  [[ "${err}" == "refusing verb" ]] || fail "$1: stderr '${err}'"
}

reset_home() {
  rm -rf "${tmp:?}/home"
  mkdir -p "${tmp}/home"
}

xena_dir="${tmp}/home/.config/xena"

run_agent health </dev/null
[[ "${code}" == "0" && "${out}" == "ok" ]] || fail "health: exit ${code}, out '${out}'"

run_agent token-put <<<"tok-fake-1"
[[ "${code}" == "0" ]] || fail "token-put: exit ${code}"
[[ "$(cat "${xena_dir}/github-token")" == "tok-fake-1" ]] || fail "token-put: wrong contents"
[[ "$(stat -c %a "${xena_dir}/github-token")" == "600" ]] || fail "token-put: wrong mode"
[[ "$(stat -c %a "${xena_dir}")" == "700" ]] || fail "token-put: wrong dir mode"
leftover=("${xena_dir}"/.github-token.*)
[[ ! -e "${leftover[0]}" ]] || fail "token-put: temp file left"

run_agent token-put </dev/null
[[ "${code}" == "1" ]] || fail "token-put empty: exit ${code}, want 1"
[[ "${err}" == "refusing empty value" ]] || fail "token-put empty: stderr '${err}'"
[[ "$(cat "${xena_dir}/github-token")" == "tok-fake-1" ]] || fail "token-put empty: token changed"

run_agent "secret-put jira-token" <<<"jira-fake"
[[ "${code}" == "0" ]] || fail "secret-put jira-token: exit ${code}"
[[ "$(cat "${xena_dir}/jira-token")" == "jira-fake" ]] || fail "secret-put jira-token: wrong contents"
[[ "$(stat -c %a "${xena_dir}/jira-token")" == "600" ]] || fail "secret-put jira-token: wrong mode"

for name in aws-credentials gcp-token; do
  run_agent "secret-put ${name}" <<<"fake-value"
  [[ "${code}" == "0" ]] || fail "secret-put ${name}: exit ${code}"
done

for cmd in "secret-put github-token" "secret-put ../x" "secret-put"; do
  run_agent "${cmd}" <<<"fake-value"
  expect_refused "${cmd}"
done

run_agent "secret-clear jira-token" </dev/null
[[ "${code}" == "0" ]] || fail "secret-clear: exit ${code}"
[[ ! -e "${xena_dir}/jira-token" ]] || fail "secret-clear: file still present"
run_agent "secret-clear jira-token" </dev/null
[[ "${code}" == "0" ]] || fail "secret-clear again: exit ${code}"

for cmd in "secret-clear github-token" "secret-clear" "secret-clear jira-token x"; do
  run_agent "${cmd}" </dev/null
  expect_refused "${cmd}"
done
[[ -e "${xena_dir}/github-token" ]] || fail "secret-clear github-token: token removed"

mkdir -p "${tmp}/home/.claude/projects/p1/memory" "${tmp}/home/.claude-mem"
echo "memory" >"${tmp}/home/.claude/projects/p1/memory/m.md"
echo "db" >"${tmp}/home/.claude-mem/db"
run_agent memory-export </dev/null
[[ "${code}" == "0" ]] || fail "memory-export: exit ${code}"
members="$(tar -tf - <"${tmp}/out")"
grep -qx ".claude/projects/p1/memory/m.md" <<<"${members}" || fail "memory-export: memory file missing"
grep -qx ".claude-mem/db" <<<"${members}" || fail "memory-export: claude-mem missing"

reset_home
run_agent memory-export </dev/null
[[ "${code}" == "0" ]] || fail "memory-export empty: exit ${code}"
[[ -z "$(tar -tf - <"${tmp}/out")" ]] || fail "memory-export empty: members listed"

src="${tmp}/src"
mkdir -p "${src}/projects/p1/memory" "${src}/claude-mem"
echo "memory" >"${src}/projects/p1/memory/m.md"
echo "CREATE TABLE t(x);" >"${src}/claude-mem/claude-mem.sql"
tar -cf "${tmp}/import.tar" -C "${src}" projects claude-mem

run_agent memory-import <"${tmp}/import.tar"
[[ "${code}" == "0" ]] || fail "memory-import: exit ${code}, stderr '${err}'"
[[ -f "${tmp}/home/.claude/projects/p1/memory/m.md" ]] || fail "memory-import: memory file missing"
[[ -f "${tmp}/home/.claude-mem/claude-mem.db" ]] || fail "memory-import: database missing"

run_agent memory-import <"${tmp}/import.tar"
[[ "${code}" == "3" ]] || fail "memory-import again: exit ${code}, want 3"
[[ "${err}" == "refusing import: memory exists" ]] || fail "memory-import again: stderr '${err}'"

reset_home
mkdir -p "${tmp}/home/.claude-mem"
touch "${tmp}/home/.claude-mem/claude-mem.db"
run_agent memory-import <"${tmp}/import.tar"
[[ "${code}" == "3" ]] || fail "memory-import with database: exit ${code}, want 3"

reset_home
mkdir -p "${tmp}/home/.claude/projects/p2/memory"
touch "${tmp}/home/.claude/projects/p2/memory/m.md"
run_agent memory-import <"${tmp}/import.tar"
[[ "${code}" == "3" ]] || fail "memory-import with memory file: exit ${code}, want 3"

reset_home
link_src="${tmp}/link-src"
mkdir -p "${link_src}/projects/p1/memory"
ln -s "${tmp}/home/.config/xena/github-token" "${link_src}/projects/p1/memory/MEMORY.md"
tar -cf "${tmp}/link.tar" -C "${link_src}" projects
run_agent memory-import <"${tmp}/link.tar"
[[ "${code}" != "0" ]] || fail "memory-import symlink: exit 0"
[[ ! -e "${tmp}/home/.claude/projects/p1/memory/MEMORY.md" && ! -L "${tmp}/home/.claude/projects/p1/memory/MEMORY.md" ]] ||
  fail "memory-import symlink: link copied"

reset_home
sql_src="${tmp}/sql-src"
mkdir -p "${sql_src}/claude-mem"
echo ".shell touch ${tmp}/pwned-sql" >"${sql_src}/claude-mem/claude-mem.sql"
tar -cf "${tmp}/sql.tar" -C "${sql_src}" claude-mem
run_agent memory-import <"${tmp}/sql.tar"
[[ ! -e "${tmp}/pwned-sql" ]] || fail "memory-import sql: dot-command ran"

reset_home
mkdir -p "${tmp}/evil"
echo "outside" >"${tmp}/evil/outside"
tar -cf "${tmp}/evil.tar" -C "${tmp}/evil" --transform 's,^,../,' outside
tar -tf "${tmp}/evil.tar" | grep -qx "../outside" || fail "memory-import traversal: bad fixture"
rm -f "${tmp}/evil/outside"
run_agent memory-import <"${tmp}/evil.tar"
[[ "${code}" != "0" ]] || fail "memory-import traversal: exit 0"
[[ -z "$(find "${tmp}" -name outside)" ]] || fail "memory-import traversal: outside created under tmp"
[[ ! -e "${TMPDIR:-/tmp}/outside" && ! -e /tmp/outside ]] || fail "memory-import traversal: outside created in temp dir"

run_agent "guard ok-case" </dev/null
[[ "${code}" == "0" && "${out}" == "guard ran" ]] || fail "guard ok-case: exit ${code}, out '${out}'"
run_agent "guard fail-case" </dev/null
[[ "${code}" == "3" ]] || fail "guard fail-case: exit ${code}, want 3"
for cmd in "guard missing-case" "guard ../lib/ok-case"; do
  run_agent "${cmd}" </dev/null
  expect_refused "${cmd}"
done

for cmd in "rm -rf /" "health now" "health;id" "health \$(id)" "HEALTH" "" "   " "token-put x" "memory-export x" \
  "memory-import x" "guard"; do
  run_agent "${cmd}" </dev/null
  expect_refused "'${cmd}'"
done
run_agent_unset
expect_refused "unset command"

cat >"${tmp}/evil.sh" <<EOF
touch "${tmp}/pwned"
EOF
BASH_ENV="${tmp}/evil.sh" run_agent health </dev/null
[[ "${code}" == "0" && "${out}" == "ok" ]] || fail "BASH_ENV health: exit ${code}, out '${out}'"
[[ ! -e "${tmp}/pwned" ]] || fail "BASH_ENV: evil.sh ran"

code=0
env "BASH_FUNC_exec%%=() { touch ${tmp}/pwned-fn; }" HOME="${tmp}/home" SSH_ORIGINAL_COMMAND=health \
  "${tmp}/lib/xena-agent" >"${tmp}/out" 2>"${tmp}/err" </dev/null || code=$?
[[ "${code}" == "0" && "$(cat "${tmp}/out")" == "ok" ]] || fail "exported function health: exit ${code}"
[[ ! -e "${tmp}/pwned-fn" ]] || fail "exported function: function ran"

echo ok
