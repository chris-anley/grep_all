#!/bin/bash
# shellcheck disable=SC2016
# grep_all.sh - A shell script that runs grep and finds security-relevant things
#--------------------------------------------------------------------------------
# Author: Chris Anley
#--------------------------------------------------------------------------------
# Ripgrep support added by Barnaby Stewart

# Tools to investigate / add
# Elixir
#     sobelow
# Golang
#     gosec
# Java
#     Dependecy Check
#     Spotbugs
#     FindSecBugs
# Javascript
#     ESLint
#     nodesecurity/eslint-plugin-security 
#     NPM Audit
#     Retire.js
#     NSP
#     ScanJS
# PHP
#     phpcs-security-audit
#     security-checker
#     PHPSecAudit
#     RIPS
# Python
#     Safety
#     PyT
# Ruby
#     GuardRails leverages Brakeman v4.3.1.
#     Bundler Audit
#     Rubocop
#     Rubocop-Gitlab-Security
#     Dawnscanner
# Solidity
#     Mythril
#     Solhint
#     MythX
# Generic
#     Detect-Secrets
#     https://github.com/Skyscanner/whispers
#     https://github.com/kevthehermit/PasteHunter
#     https://github.com/emanuil/php-reaper
#     retire.js
#     Visual Code Grep
# Dependency Checkers
#     Bundler-Audit (Ruby)
#     Dependency-check (OWASP) - Out of date third-party components
#     Node Security Project - NSP
#     OSSIndex

# Tools that can't easily be run in a script:
# todo: tailor - static analysis for swift
# RIPS
# https://www.owasp.org/index.php/OWASP_LAPSE_Project lapse - java ee scanner
# Findbugs - java
# safesql - go sql injection static analysis - requires 'go' build
# go get github.com/stripe/safesql
# Dawnscanner
# phpmetrics - html - dependencies
# todo: WinBinAudit.exe <file>
# TODO: Exclude output directory from results
# TODO: -vvvvv output filters by report level, default = ~zero fp, 5 = everything
# TODO More tools to add: https://docs.gitlab.com/ee/user/application_security/sast/
# TODO: strcpy_s etc, flaws per Robert's paper
# TODO: strlcpy, strscpy with sizeof() wrong argument
#   also without sizeof correct argument
# TODO: Extend ptr += snprintf() to other functions returning n bytes copied
# TODO ruby on rails \.select(.{0,99}".{0,99}$
# TODO ruby on rails \.where(.{0,99}".{0,99}$
# return network code locations in c/c++ and c#.
# Michael Howard's banned list: https://github.com/x509cert/banned
# TODO: ()-> for null ptr deref?
# grep: \(\)->\w+\(\)->   double function deref
# grep: and, followed by or, followed by dereference:
# TODO: Add false positive detection in greps, i.e. xss not present if encoded.
# todo: awap / wap - php static analysis: ./wap -a -all -p ~/code -out /tmp/out/wap.txt
# todo: clang-analyzer
# todo: grep log output from syslog etc, for failed logins; username is often password

# Dependencies:
# brew install python
# pip install bandit
# pip install safety
# brew install flawfinder
# brew install cppcheck
# brew install shellcheck
# brew install cloc
# brew install infer
# brew install homebrew/php/phpmetrics
# brew install node
# npm install -g retire
# npm install -g nsp
# brew install clamav
#      freshclam


#region Debugging/Output

DEBUG=
VERBOSE=

YELLOW="\e[33m"  # Warnings
BLUE="\e[94m"    # Verbose
BOLD="\e[1m"    # Bold text
ENDCOLOR="\e[0m" # Reset


function verbose() {
  # Used to enhance information to the user
  if [ -n "$VERBOSE" ]; then
    echo -en "$BLUE"
    echo -n "[*]" "$@"
    echo -e "$ENDCOLOR"
  fi
}

function debug() {
  # Used to enhance information to the user
  if [ -n "$DEBUG" ]; then
    echo -en "${BLUE}"
    echo -n "[DEBUG]" "$@"
    echo -e "$ENDCOLOR"
  fi
}

function warn() {
  # Used to warning the user about an action that errored/failed
  echo -en "${YELLOW}"
  echo -n "[!]" "$@"
  echo -e "${ENDCOLOR}"
}

function info() {
  # Generic messages to the user
  echo -en "${BOLD}"
  echo -n "[+]" "$@"
  echo -e "${ENDCOLOR}"
}

#endregion

function show_help() {
  echo
  echo 'grep_all.sh - Security Review Script'
  echo 'WARNING: THIS SCRIPT MAY DAMAGE YOUR COMPUTER. RUN IT AT YOUR OWN RISK.'
  echo 
  echo 'USAGE'
  echo '  $ grep_all.sh [-v] [-r] <output directory> [code directory]'
  echo 
  echo '      -v/--verbose      :   (Optional) Output verbose messages'
  echo '      -r/--ripgrep      :   (Optional) Use rg instead of grep to perform regex matches'
  echo '      <output directory>:   The location to write the results'
  echo '      [code directory]  :   (Optional) The location of code to audit'
  echo
  echo '  To grep_all (audit) the current directory, just specify the output path:'
  echo '    $ cd /mnt/project/src/code'
  echo '    $ grep_all.sh ~/path/to/output'
  echo 
  echo '  To audit a specific directory, provide both the output path and code path:'
  echo '    $ grep_all.sh ~/path/to/output ~/path/to/code'
  echo ''
  echo '  If you have ripgrep (rg) installed, specify -r or --ripgrep to get a performance improvement'
  echo '    $ grep_all.sh -r ~/path/to/output'
  echo 
  echo 'REMARKS'
  echo '  This script can take a long time to run. If you terminate the script, then rerun with the same arguments.'
  echo '  If it is terminated early, you may lose the output from the command(s) currently running.'
  echo '  However, the script will generally pick up where they left off.'
  echo
  
}


if [ -z "$1" ]; then
  show_help
  exit
fi

do_ripgrep="false"

for arg in in "$@"
do
  case "$arg" in
    "-h" | "--help") 
      show_help; 
      exit ;;
    "-r" | "--ripgrep")     
      if [ -z "$(which rg)" ] ; then
        warn "Ripgrep requested but not found. Rerun without '-r'/'--ripgrep' or install ripgrep then run again."
        exit
      fi
      do_ripgrep="true" ;;
    "-v" | "--verbose") 
      VERBOSE=1 ;;
    "-d" | "--debug") 
      DEBUG=1 ;;
  esac
done

# Shift parameters so output/code paths are correct
[ -n "$VERBOSE" ] && shift && verbose "Verbose parameter detected"
[ -n "$DEBUG" ] && shift  && debug "Debug parameter detected"
[ "$do_ripgrep" == "true" ] && shift && info "Ripgrep mode selected"


# Track relative and absolute paths, as we will be CDing into the code directory.
out_original=$1
out=$(realpath "$out_original")
code_directory=""
current_dir=$(pwd)
scriptDir=$(dirname "$0")

# Switch to code dir if provided
if  [ -n "$2" ] ; then 
  cd "$2" || { 
    warn "Directory '$2' does not exist."
    show_help
    exit
  }
  
  code_directory=$2
  current_dir=$(pwd)
fi
#endregion

debug "\$out => $out"
debug "\$current_dir => $current_dir"
debug "\$scriptDir => $scriptDir"

info "Writing to output directory: $out"
if [ ! -e "$out" ]; then
  mkdir -p "$out"
fi

info "Reading from: $current_dir"

#region Escaping greps: the following chars need escaping: (){}?+ and space
# Define format first, putting word boundaries on the actual lookups
domainNameFormat='(([A-Z0-9][A-Z0-9-]{1,80}\.){1,}(aero|arpa|asia|biz|cat|com|coop|edu|gov|inet|jobs|mil|mobi|museum|org|ru|pro|tel|travel|u[ks]|xxx)'

# Word boundaries will speed up matches signficantly.
domainName="\b${domainNameFormat}\b"
emailAtDomain="\b([.\-_a-zA-Z0-9]{1,80}\@${domainNameFormat})\b"
#endregion

# secret grep-fu; restrict to ascii for performance
# Also, USE GNU GREP (it's 10x faster than OSX/BSD grep)
LC_ALL=C
LANG=C

#region Library functions - e.g. do_xxxx, rm_if_xxxxx
function rm_if_empty() {
  test -s "${1}" || rm "${1}" && debug "rm_if_empty: File deleted: $1"
}
function rm_if_present() {
  test -e "${1}" && rm "${1}" && debug "rm_if_present: File deleted: $1"
}

function grep_filter() {
  #cat
  #grep -vi '\.xml' | grep -vi '\.js' | grep -vi '\.css' |
  grep -Pviq --binary-files=text '(binary file|/third_party/|/test/|example|/node_modules/|/packages/|/obj/|/bin/|/vendor/|/\.svn/)'
}

# do_grep <expression> <output-file> <grep-options> <filter-cmd>
function do_plaingrep() {
  if [ -e "$out/$2" ]; then return; fi

  if [ -z "$3" ]; then
    grep_opts="-Prn"
  else
    grep_opts="-Prn $3"
  fi

  debug "do_plaingrep: "
  debug "  \$1 => $1"
  debug "  \$2 => $2"
  debug "  \$3 => $3"
  debug "  \$4 => $4"

  # If extra commands are required
  if [ -n "$4" ]; then
    echo "grep \"$grep_opts\" \"$1\" \"$code_directory\" | grep_filter | sh -c \"$4\" > \"$out_original/$2\""
    grep "$grep_opts" "$1" "$(pwd)" | grep_filter | sh -c "$4" > "$out/$2"
  else 
    echo "grep \"$grep_opts\" \"$1\" \"$code_directory\" | grep_filter > \"$out_original/$2\""
    grep "$grep_opts" "$1" "$(pwd)" | grep_filter >"$out/$2"  
  fi

  rm_if_empty "$out/$2"
}
  
# Takes a filelist, greps all files listed within
function do_filelist_grep() {
  # do_filelist_grep <expression> <output-file> <input-filelist> <grep-opts>

  debug "do_filelist_grep: "
  debug "  \$1 => $1"
  debug "  \$2 => $2"
  debug "  \$3 => $3"
  debug "  \$4 => $4"
  
  grep_opts="-Prn"
  
  if [ -n "$4" ]; then
    grep_opts="${grep_opts} $4"
  fi

  # Skip checks if a file doesn't exist
  if [ ! -s "$out/$3" ]; then   
    verbose "do_filelist_grep: Skipped (no files): <$3 xargs grep ${grep_opts} '$1' >> $2"
    return
  fi

  echo "<$3 xargs grep ${grep_opts} '$1' >> $2"
  
  if [ ! -s "$out/$2" ]; then
    < "$out/$3" xargs -d '\n' grep "$grep_opts" "$1" > "$out/$2"

    # Check verbose flag directly, as this has an overhead
    if [ -n "$VERBOSE" ]; then
      if [ -s "$out/$2" ]; then 
          verbose "do_filelist_grep: $2 >>" "$(wc -l < "$out_original/$2")" "result(s)"
      fi
    fi
  fi

  rm_if_empty "$out/$2"
}

function do_ripgrep() {
  if [ -e "$out/$2" ]; then return; fi

  rg_args=(--no-heading -Pn) # ripgrep is more sensitive to how arguments are passed - array required
  if [ -n "$3" ]; then # convert grep style includes to ripgrep
    grep_args="$(sed 's|--include=\(\S*\)|-g \1|g' <<<"$3")"
    grep_args="$(sed 's|--exclude=\(\S*\)|-g !\1|g' <<<"$grep_args")"
    IFS=' ' read -ra args_array <<<"${grep_args}"
    rg_args+=("${args_array[@]}")
  fi
  rg_args+=("$1" "$(pwd)")

  if [ -z "$4" ]; then
    # shellcheck disable=SC2059,SC2068
    echo "rg " ${rg_args[@]} "| grep_filter > $out_original/$2"
    rg "${rg_args[@]}" | grep_filter >"$out/$2"
  else
    # shellcheck disable=SC2059,SC2068
    echo "rg " ${rg_args[@]} "| grep_filter | sh -c $4 > $out_original/$2"
    rg "${rg_args[@]}" | grep_filter | sh -c "$4" >"$out/$2"
  fi

  rm_if_empty "$out/$2"
}

function do_plaingrep_return_uniq_token() {
  if [ ! -e "$out/$2" ]; then
    echo "grep -Pra $1 $(pwd) | grep_filter | grep -Poa $1 | sort -u > $out_original/$2"
    grep -Pra "$1" "$(pwd)" | grep_filter | grep -Poa "$1" | sort -u >"$out/$2"
    rm_if_empty "$out/$2"
  fi
}

function do_ripgrep_return_uniq_token() {
  if [ ! -e "$out/$2" ]; then
    echo "rg --no-heading -Pa $1 | grep_filter | grep -Po $1 | sort -u > $out_original/$2"
    rg -Pa "$1" | grep_filter | grep --binary-files=text -Po "$1" | sort -u >"$out/$2"
    rm_if_empty "$out/$2"
  fi
}

if [ "$do_ripgrep" == "true" ]; then
  function do_grep() { do_ripgrep "$@"; }
  function do_grep_return_uniq_token() { do_ripgrep_return_uniq_token "$@"; }
else
  function do_grep() { do_plaingrep "$@"; }
  function do_grep_return_uniq_token() { do_plaingrep_return_uniq_token "$@"; }
fi

function do_exec() {
  debug "do_exec: "
  debug "  \$1 => $1"
  debug "  \$2 => $2"

  if [ ! -e "$out/$2" ]; then
    echo "$1"
    eval "$1" &>"$out/$2"
    rm_if_empty "$out/$2"
  fi
}

function join_array() {
  local IFS="${1}"
  shift
  echo "$*"
}
function do_fast_banned_grep() {
  combinedfile="${out}/banned_combined_results.txt"

  info "grep for all banned functions to combined results"

  # shellcheck disable=SC2068
  pattern="[\W^]($(join_array '|' ${BannedFunctions[@]}))\s*\(.{0,99}$"
  if [ "${do_ripgrep}" == "true" ]; then
    grep_args="$(sed 's|--include=\(\S*\)|-g \1|g' <<<"$C_FILES")"
    grep_args="$(sed 's|--exclude=\(\S*\)|-g !\1|g' <<< "$grep_args")"

    IFS=' ' read -ra args_array <<<"${grep_args}"

    #shellcheck disable=SC2206,SC2207
    grep_args=(-Pn --no-heading "${args_array[@]}" \"${pattern}\" \"$(pwd)\")

    # shellcheck disable=SC2059,SC2145
    verbose "rg ${grep_args[@]} | grep_filter > \"${combinedfile}\""

    # shellcheck disable=SC2068
    rg ${grep_args[@]} | grep_filter > "${combinedfile}"
  else
    IFS=' ' read -ra args_array <<<"${C_FILES}"

    #shellcheck disable=SC2206,SC2207
    grep_args=(-Prn "${args_array[@]}" \"${pattern}\" \"$(pwd)\")

    # shellcheck disable=SC2059,SC2145,SC2068
    verbose "grep ${grep_args[@]} | grep_filter > \"${combinedfile}\""

    # shellcheck disable=SC2068
    grep ${grep_args[@]} | grep_filter > "${combinedfile}"
  fi

  info "splitting grep results"
  for fn in "${BannedFunctions[@]}"; do
    debug "do_fast_banned_grep: grep \"-P\" \"[\W^]${fn}\s*\(.{0,99}$\" \"${combinedfile}\" > \"${out}/banned_${fn}.txt\""
    grep "-P" "[\W^]${fn}\s*\(.{0,99}$'" "${combinedfile}" > "${out}/banned_${fn}.txt"
    rm_if_empty "${out}/banned_${fn}.txt"
  done
  rm "${combinedfile}"
}

#endregion


info Starting Greps
start_time=$(date +%s)

do_exec 'echo `date`' 'basic_begin.txt'
do_exec "echo $(pwd)" 'basic_path.txt'

# infer (static analysis tool)
# infer -a checkers --bufferoverrun -- make
# if you can run 'make', you can run infer. But it's very false-positivey
# dependency-check --project scan -o "$out" -s .

if true; then

  do_exec "find . -name 'requirements.txt' -exec sh -c 'echo {}; safety check --full-report -r {}' \;" 'tool_safety.txt'

  #echo '# Count of files by extension'
  do_exec "find . -type f | grep -E '.*\.[a-zA-Z0-9]*$' | sed -e 's/.*\(\.[a-zA-Z0-9]*\)$/\1/' | sort | uniq -c | sort -n" 'basic_extensions.txt'
  #
  #echo '# CLOC - Count Lines Of Code'
  do_exec 'cloc --progress-rate=0 .' 'basic_cloc.txt' & # background cloc because it can take a very long time + its a bit tedious
  #
  #echo '# Clam Antivirus Scan'
  do_exec 'clamscan -r .' 'tool_clamav.txt' &
  #
  # WAP - php "web application protection" scanner
  # WAP needs special handling; it must be run from its own install directory.
  do_exec "cd ~/wap-2.1/; echo | ./wap -a -all -p '$current_dir'; cd $current_dir" 'tool_wap.txt' &
  #
  # find suid binaries
  do_exec 'find . -perm +6000 -type f -exec ls -ld {} \; ' 'suid.txt' &
  do_exec 'find . -user root -perm -4000 -print ' 'suid2.txt' &
  #
  # shell check - shell script static analysis
  do_exec 'find . -type f -name *.sh -exec shellcheck {} \;' 'tool_shellcheck.txt' &
  #
  # Find git repositories
  do_exec 'find . -name .git' 'info_git_repositories.txt' &
  #
  # Find dot files
  do_exec 'find . -name ".*"' 'info_dot_files.txt' &
  #
  # cppcheck - c / cpp static analysis
  #do_exec 'find . "( -name *.c -o -name *.cpp -o -name *.cxx -o -name *.cc )" -exec cppcheck --force \{\} \;' 'tool_cppcheck.txt' &  # Background, because long-running
  #
  # Flawfinder - c / cpp static analysis (very false-positivey)
  do_exec 'flawfinder .' 'tool_flawfinder.txt' &
  #
  # Bandit - python static analysis
  do_exec 'bandit --ignore-nosec -r .' 'tool_bandit.txt' & # Background, long running
  #
  # Find 'secret' files
  do_exec 'find . -name '\''*secret*'\' 'bug_secret_files.txt'

  # Find 'pickle' files
  do_exec 'find . -name '\''*.pkl'\' 'bug_pickle_files.txt'

  # Find model files
  do_exec 'find . -name '\''*.hdf5'\' 'bug_ml_model_files_hdf5.txt'
  do_exec 'find . -name '\''*.hd5'\' 'bug_ml_model_files_hd5.txt'
  do_exec 'find . -name '\''*.h5'\' 'bug_ml_model_files_h5.txt'
  do_exec 'find . -name '\''*.pt'\' 'bug_ml_model_files_pt.txt'

  # NSP - Node security project. Looks for package.json in project directories. Summary because it's one line per bug.
  # npm install -g nsp
  # find . ( -name package.json ) -exec echo {} \;
  # nsp check ./server/ --reporter summary
  # find . -name package.json | while read i; do dirname $i; done | while read j; do echo PROJECT: $j; nsp check $j --reporter json | jq -j '.[] | .title, "-", .cvss_score, "\n"'; done
  #.id, "\t", .title, "\t", .advisory, "\t", .path
  do_exec 'find . -name package.json | while read i; do dirname $i; done | while read j; do echo PROJECT: $j; cd $j; npm audit; done' 'tool_npm.txt'

  # Brakeman
  for d in $(find . | grep config/routes.rb | sed -E 's/config\/routes\.rb//'); do

    #shellcheck disable=SC2059
    filename=$(printf "$d" | tr -C '[:alnum:]' '_')
    brakeman --absolute-paths -o "$out/tool_brakeman_$filename.txt" -o "$out/tool_brakeman_$filename.html"
  done

  # npm i -g eslint
  # npm install -g eslint-plugin-security
  # note - this requires careful config beforehand to import the security rules
  do_exec 'eslint .' 'tool_eslint.txt'

#PHPMetrics - php code metrics thing
#do_exec "phpmetrics --report-html $out/phpmetrics.html ." "tool_phpmetrics.txt"

# retire.js - detects out of data js dependencies
# do_exec 'retire --path .' 'tool_node_retire.txt'

fi

#region File List Grepping initialization

## Find the specific file types, then run the rules specifically for those
## Can be run in parallel, as there is no FS recursion, so very fast!

# Filter criteria (used by find . )
APPLE_FILELIST_FILTER="'.*\.(swift|m|plist|c|h|cpp|cxx|cc|C|hpp)'"
C_FILELIST_FILTER="'.*\.(c|h|cpp|cxx|cc|C|hpp)'"
CS_FILELIST_FILTER="'.*\.cs'"
GO_FILELIST_FILTER="'.*\.go'"
JAVA_FILELIST_FILTER="'.*\.java'"
PHP_FILELIST_FILTER="'.*\.(php|php3|php4|php5|phtml|inc)'"
PYTHON_FILELIST_FILTER="'.*\.py'"
RUBY_FILELIST_FILTER="'.*\.rb'"

# Output files for filtering
APPLE_FILELIST='info_apple_filelist.txt'
C_FILELIST='info_c_filelist.txt' 
CS_FILELIST='info_cs_filelist.txt'
GO_FILELIST='info_go_filelist.txt'
JAVA_FILELIST='info_java_filelist.txt'
PHP_FILELIST='info_php_filelist.txt'
PYTHON_FILELIST='info_py_filelist.txt'
RUBY_FILELIST='info_ruby_filelist.txt'

#endregion

## Specific includes for normal grepping
#APPLE_FILES='--include=*.swift --include=*.m --include=*.plist --include=*.c --include=*.h --include=*.cpp --include=*.cxx --include=*.cc --include=*.C --include=*.hpp'
C_FILES='--include=*.c --include=*.h --include=*.cpp --include=*.cxx --include=*.cc --include=*.C --include=*.hpp'
CS_FILES='--include=*.cs'
#GO_FILES='--include=*.go'
#PHP_FILES='--include=*.php --include=*.php3 --include=*.php4 --include=*.php5 --include=*.phtml --include=*.inc'
#JAVA_FILES='--include=*.java'
#PYTHON_FILES='--include=*.py'
#RUBY_FILES='--include=*.rb'

BannedFunctions=('_alloca' '_ftcscat' '_ftcscpy' '_getts' '_gettws' '_i64toa' '_i64tow' '_itoa' '_itow' '_makepath' '_mbccat' '_mbccpy' '_mbscat' '_mbscpy' '_mbslen' '_mbsnbcat' '_mbsnbcpy' '_mbsncat' '_mbsncpy' '_mbstok' '_mbstrlen' '_sntscanf' '_splitpath' '_stprintf' '_stscanf' '_tccat' '_tccpy' '_tcscat' '_tcscpy' '_tcsncat' '_tcsncpy' '_tcstok' '_tmakepath' '_tscanf' '_tsplitpath' '_ui64toa' '_ui64tot' '_ui64tow' '_ultoa' '_ultot' '_ultow' '_vstprintf' '_wmakepath' '_wsplitpath' 'alloca' 'ChangeWindowMessageFilter' 'CharToOem' 'CharToOemA' 'CharToOemBuffA' 'CharToOemBuffW' 'CharToOemW' 'CopyMemory' 'gets' 'IsBadCodePtr' 'IsBadHugeReadPtr' 'IsBadHugeWritePtr' 'IsBadReadPtr' 'IsBadStringPtr' 'IsBadWritePtr' 'lstrcat' 'lstrcatA' 'lstrcatn' 'lstrcatnA' 'lstrcatnW' 'lstrcatW' 'lstrcpy' 'lstrcpyA' 'lstrcpyn' 'lstrcpynA' 'lstrcpynW' 'lstrcpyW' 'lstrlen' 'lstrncat' 'makepath' 'memcpy' 'memcpy' 'OemToChar' 'OemToCharA' 'OemToCharW' 'RtlCopyMemory' 'scanf' 'snscanf' 'snwscanf' 'sprintf' 'sprintfA' 'sscanf' 'strcat' 'strcat' 'StrCat' 'strcatA' 'StrCatA' 'StrCatBuff' 'StrCatBuffA' 'StrCatBuffW' 'StrCatChainW' 'StrCatN' 'StrCatNA' 'StrCatNW' 'strcatW' 'StrCatW' 'strcpy' 'StrCpy' 'strcpyA' 'StrCpyA' 'StrCpyN' 'StrCpyNA' 'strcpynA' 'StrCpyNW' 'strcpyW' 'StrCpyW' 'strlen' 'StrLen' 'strncat' 'StrNCat' 'StrNCatA' 'StrNCatW' 'strncpy' 'StrNCpy' 'StrNCpyA' 'StrNCpyW' 'strtok' 'swprintf' 'swscanf' 'vsnprintf' 'vsprintf' 'vswprintf' 'wcscat' 'wcscpy' 'wcslen' 'wcsncat' 'wcsncpy' 'wcstok' 'wmemcpy' 'wnsprintf' 'wnsprintfA' 'wnsprintfW' 'wscanf' 'wsprintf' 'wsprintf' 'wsprintfA' 'wvnsprintf' 'wvnsprintfA' 'wvnsprintfW' 'wvsprintf' 'wvsprintfA' 'wvsprintfW')

# Filter relevant files 
do_exec "find . -iregex $APPLE_FILELIST_FILTER" "$APPLE_FILELIST"
do_exec "find . -iregex $C_FILELIST_FILTER" "$C_FILELIST"
do_exec "find . -iregex ${CS_FILELIST_FILTER}" "$CS_FILELIST"
do_exec "find . -iregex $GO_FILELIST_FILTER" "$GO_FILELIST" 
do_exec "find . -iregex $JAVA_FILELIST_FILTER" "$JAVA_FILELIST"
do_exec "find . -iregex $PHP_FILELIST_FILTER" "$PHP_FILELIST" 
do_exec "find . -iregex $PYTHON_FILELIST_FILTER" "$PYTHON_FILELIST" 
do_exec "find . -iregex $RUBY_FILELIST_FILTER" "$RUBY_FILELIST" 

## Below statements are all run in parallel, as grepping will be extremely fast.

# Apple
echo 
info "Starting Apple specific checks"
do_filelist_grep 'KeychainItem.{0,200}$' 'info_apple_keychain_item.txt' "$APPLE_FILELIST" 
do_filelist_grep 'kSecValueData.{0,200}$' 'info_apple_ksecvaluedata.txt' "$APPLE_FILELIST"
do_filelist_grep 'SecItemUpdate.{0,200}$' 'info_apple_secitemupdate.txt' "$APPLE_FILELIST"

# PHP 
echo 
info "Starting PHP specific checks"
do_filelist_grep '\.\s+\$_GET.{0,99}$' 'bug_php_get_param_in_string.txt' "$PHP_FILELIST"
do_filelist_grep '\.\s+\$_POST.{0,99}$' 'bug_php_post_param_in_string.txt' "$PHP_FILELIST"
do_filelist_grep '\.\s+\$_COOKIE.{0,99}$' 'bug_php_cookie_param_in_string.txt' "$PHP_FILELIST"
do_filelist_grep '\.\s+\$_REQUEST.{0,99}$' 'bug_php_request_param_in_string.txt' "$PHP_FILELIST"
do_filelist_grep 'create_function.{0,99}$' 'bug_php_create_function.txt' "$PHP_FILELIST"
do_filelist_grep 'filter_input.{0,99}$' 'bug_php_filter_input.txt' "$PHP_FILELIST"
do_filelist_grep '(include|require).{0,99}\$.{0,99}$' 'bug_php_var_include.txt' "$PHP_FILELIST"
do_filelist_grep '\$\w+\(.{0,99}$' 'bug_php_var_func.txt' "$PHP_FILELIST"
do_filelist_grep 'order\s+by.{0,200}'\''.{0,200}\$.{0,200}$' 'bug_php_order_by.txt' "$PHP_FILELIST"
do_filelist_grep '\W(mt_rand|mt_srand|lcg_value|rand|uniqid|microtime|shuffle)\W.{0,99}$' 'bug_php_bad_rand.txt' "$PHP_FILELIST"
do_filelist_grep '\W(openssl_random_pseudo_bytes|random_int|random_bytes)\W.{0,99}$' 'info_php_good_rand.txt' "$PHP_FILELIST"
do_filelist_grep 'assert\(\s*"?\$\w*"?\s*\).{0,99}$' 'bug_php_rce_assert.txt' "$PHP_FILELIST"
do_filelist_grep 'eval\(\s*"?\$\w*"?\s*\).{0,99}$' 'bug_php_rce_eval.txt' "$PHP_FILELIST"
do_filelist_grep '_protect_identifiers.*FALSE.{0,99}$' 'bug_php_sqli_codeigniter_disable_escape.txt' "$PHP_FILELIST"
do_filelist_grep 'select\(.*FALSE.{0,99}$' 'bug_php_sqli_codeigniter_select_disable_escape.txt' "$PHP_FILELIST"
do_filelist_grep 'CURLOPT_SSL_VERIFYHOST\s*[=>,]*\s+(false|0).{0,99}$' 'bug_php_ssl_disable_curl.txt' "$PHP_FILELIST"
do_filelist_grep '\$_COOKIE.{0,99}$' 'info_php_cookie.txt' "$PHP_FILELIST"
do_filelist_grep '\$_GET.{0,99}$' 'info_php_get.txt' "$PHP_FILELIST"
do_filelist_grep '\$_POST.{0,99}$' 'info_php_post.txt' "$PHP_FILELIST"
do_filelist_grep '\$_REQUEST.{0,99}$' 'info_php_request.txt' "$PHP_FILELIST"
do_filelist_grep '\Wpopen\s*\(.{0,200}$' 'info_php_popen.txt' "$PHP_FILELIST"
do_filelist_grep '\Wpopen.*\(.*\$.*\).{0,99}$' 'bug_php_cmdi_popen_var.txt' "$PHP_FILELIST"
do_filelist_grep '\Wexec\s*\(.{0,200}$' 'info_php_exec.txt' "$PHP_FILELIST"
do_filelist_grep 'shell_exec\s*\(.{0,200}$' 'info_php_shell_exec.txt' "$PHP_FILELIST"
do_filelist_grep 'proc_open\s*\(.{0,200}$' 'info_php_proc_open.txt' "$PHP_FILELIST"
do_filelist_grep 'escapeshellarg\s*\(.{0,200}$' 'info_php_escapeshellarg.txt' "$PHP_FILELIST"
do_filelist_grep 'file_get_contents\s*\(.{0,200}$' 'info_php_filegetcontents.txt' "$PHP_FILELIST"
do_filelist_grep 'parse_str\s*\([^\n,]{0,200}$' 'bug_php_parse_str_no_param.txt' "$PHP_FILELIST"
do_filelist_grep 'strcmp.*==.{0,200}$' 'bug_php_strcmp_array_bypass.txt'  "$PHP_FILELIST"
do_filelist_grep 'strcmp.{0,200}$' 'info_php_strcmp.txt'  "$PHP_FILELIST"
# TODO: BACKTICK do_grep '\Wshell_exec\(.{0,200}$' 'info_php_exec.txt' "$PHP_FILES"

### Ruby rules
echo 
info "Starting Ruby specific checks"
do_filelist_grep '\Wget\s' 'info_ruby_route_get.txt' "$RUBY_FILELIST"
do_filelist_grep '\Wpost\s' 'info_ruby_route_post.txt' "$RUBY_FILELIST"
do_filelist_grep '\Wput\s' 'info_ruby_route_put.txt' "$RUBY_FILELIST"
do_filelist_grep '\Wdelete\s' 'info_ruby_route_delete.txt' "$RUBY_FILELIST"
do_filelist_grep '\Wmatch\s' 'info_ruby_route_match.txt' "$RUBY_FILELIST"
do_filelist_grep 'IO\.popen.*#\{' 'bug_ruby_cmdi_popen.txt' "$RUBY_FILELIST"
do_filelist_grep 'IO\.popen' 'info_ruby_cmdi_popen.txt' "$RUBY_FILELIST"
do_filelist_grep 'Process\.spawn.*#\{' 'bug_ruby_cmdi_spawn.txt' "$RUBY_FILELIST"
do_filelist_grep 'Process\.spawn' 'info_ruby_cmdi_spawn.txt' "$RUBY_FILELIST"
do_filelist_grep '%x[\(\{].*#\{' 'bug_ruby_cmdi_percent_x.txt' "$RUBY_FILELIST"
do_filelist_grep '^[^"\n]*`[^`\n]*#\{[^`\n]+`' 'bug_ruby_cmdi_backtick.txt' "$RUBY_FILELIST"
do_filelist_grep '^[^"\n]*`[^`\n]+`' 'info_ruby_cmdi_backtick.txt' "$RUBY_FILELIST"
do_filelist_grep '%x[\(\{]' 'info_ruby_cmdi_percent_x.txt' "$RUBY_FILELIST"
do_filelist_grep '\Wexec\W' 'info_ruby_cmdi_exec.txt' "$RUBY_FILELIST"
do_filelist_grep '\Wsystem\W.*#\{' 'bug_ruby_cmdi_system.txt' "$RUBY_FILELIST"
do_filelist_grep '\WENV\[".*"\]' 'info_ruby_env.txt' "$RUBY_FILELIST"
do_filelist_grep '(Digest::MD5|Digest::SHA1)' 'info_ruby_bad_hash.txt' "$RUBY_FILELIST"
do_filelist_grep '\.headers\["[a-zA-Z0-9-]"\]' 'info_ruby_req_header.txt' "$RUBY_FILELIST"
do_filelist_grep '\Wwhere\(.*#' 'info_ruby_sqli_where.txt' "$RUBY_FILELIST"
do_filelist_grep '\Wfrom\(.*#' 'info_ruby_sqli_where.txt' "$RUBY_FILELIST"
do_filelist_grep '\Worder\(.*#' 'info_ruby_sqli_order.txt' "$RUBY_FILELIST"
do_filelist_grep '"[^"#]*#\{' 'info_ruby_string_interpolation.txt' "$RUBY_FILELIST"
do_filelist_grep 'https?://.*#\{.{0,99}$' 'bug_ruby_url_string_interpolation.txt' "$RUBY_FILELIST"

#region C# Rules
echo 
info "Starting C# specific checks"
do_filelist_grep '\.AppendFormat.{1,80}\{\d+\}.{0,199}$' 'info_cs_appendformat.txt' "$CS_FILELIST"
do_filelist_grep '=\s*{.{0,200}$' 'info_cs_sqli_interpolation.txt' "$CS_FILELIST"
do_filelist_grep '".{0,99}\Wand\W.{0,99}".{0,99}\+.{0,99}$' 'info_cs_sqli_and.txt' "$CS_FILELIST"
do_filelist_grep 'SkipAuthorization.{0,100}$' 'bug_cs_skip_auth.txt' "$CS_FILELIST"
do_filelist_grep 'location.{0,10}path.{0,10}=.{0,100}$' 'info_cs_app_paths.txt' "$CS_FILELIST"
do_filelist_grep 'allow.{0,10}users.{0,10}\*.{0,100}$' 'bug_cs_allow_all.txt' "$CS_FILELIST"
do_filelist_grep 'allow.{0,10}users.{0,10}=.{0,100}$' 'info_cs_allow_users.txt' "$CS_FILELIST"
do_filelist_grep 'FormsAuthentication.{0,199}$' 'info_cs_forms_authentication.txt' "$CS_FILELIST"
do_filelist_grep '\WSystem\.Security\.Cryptography\W.{0,199}$' 'info_cs_crypto.txt' "$CS_FILELIST"
do_filelist_grep '\WBinaryWrite\W.{0,199}$' 'info_cs_binarywrite.txt' "$CS_FILELIST"
do_filelist_grep '\WWriteFile\W.{0,199}$' 'info_cs_writefile.txt' "$CS_FILELIST"
do_filelist_grep '^.{0,199}'\''\{\s*\d+\s*\}'\''.{0,199}$' 'bug_sqli_interpolate_brace.txt' "$CS_FILELIST"
do_filelist_grep '"select.{0,199}\{.{0,199}$' 'bug_sqli_select_brace.txt' "$CS_FILELIST"
do_filelist_grep '\sSimpleDB\..{0,99}$' 'bug_cs_sqli_simpleDB.txt' "$CS_FILELIST"
do_filelist_grep '\W(SqlClient|SqlCommand).{0,99}$' 'bug_cs_sqlClient.txt'  "$CS_FILELIST"
do_filelist_grep '\W(ExecuteSqlCommand|ExecuteSqlCommandAsync|SqlQuery).{0,99}$' 'bug_cs_sqlCmd.txt' "$CS_FILELIST"
do_filelist_grep '\WSqlConnection.{0,99}$' 'bug_cs_sqlConnection.txt' "$CS_FILELIST"
do_filelist_grep '\sunsafe\s.{0,99}$' 'info_cs_unsafe.txt' "$CS_FILELIST"
do_filelist_grep '(Replace\("\""|Replace\("'\''").{0,99}$' 'bug_cs_replaceQuote.txt' "$CS_FILELIST"
do_filelist_grep 'Replace.{0,99}'\''.{0,99}'\'\''.{0,99}$' 'bug_cs_sqli_doubleupquote.txt' "$CS_FILELIST"
do_filelist_grep 'HttpCookie.{0,99}$' 'info_cs_cookie.txt' "$CS_FILELIST"
do_filelist_grep 'DisableSecurity.{0,99}$' 'bug_cs_disablesecurity.txt' "$CS_FILELIST"
do_filelist_grep '\[ValidateInput.{1,20}false.{0,99}$' 'bug_cs_validateinput_false.txt' "$CS_FILELIST"
do_filelist_grep '\WResponse\..{0,99}$' 'info_cs_response_object.txt' "$CS_FILELIST"
do_filelist_grep '\WRequest\..{0,99}$' 'info_cs_request_object.txt' "$CS_FILELIST"
do_filelist_grep 'TripleDESCryptoServiceProvider.{0,99}$' 'bug_cs_tripledes.txt'  "$CS_FILELIST"
do_filelist_grep 'CipherMode\.ECB.{0,99}$' 'bug_cs_weak_ecb_mode.txt' "$CS_FILELIST"
do_filelist_grep '\[Http(Post|Get|Patch|Put|Delete).{0,99}$' 'info_cs_method.txt' "$CS_FILELIST"
do_filelist_grep '\.MapRoute\(.{0,299}$' 'info_cs_route.txt' "$CS_FILELIST"
do_filelist_grep 'Page_Load.{0,99}$' 'info_cs_pageload.txt' "$CS_FILELIST"
do_filelist_grep '\[(WebMethod|WebService|ScriptMethod|ScriptService).{0,99}$' 'info_cs_webmethod.txt'  "$CS_FILELIST"
do_filelist_grep '\[AllowAnonymous\].{0,99}$' 'info_cs_allowanonymous.txt' "$CS_FILELIST"
do_filelist_grep '\.Encrypt\(.{1,99}false.{0,99}$' 'bug_cs_insecure_rsa_padding.txt' "$CS_FILELIST"
do_filelist_grep '(RIPEMD160|SHA1|MD5|MD2|MD4).{0,99}(.{0,99}){0,99}$' 'bug_web_dotnet_weak_hash.txt' "$CS_FILELIST"
do_filelist_grep '\W(SqlClient|SqlCommand).{0,99}$' 'info_cs_sqlclient.txt' "$CS_FILELIST"
do_filelist_grep '\W(ExecuteSqlCommand|ExecuteSqlCommandAsync|SqlQuery).{0,99}$' 'info_cs_sqlcommand.txt' "$CS_FILELIST"
do_filelist_grep '^\s*\[Obsolete.*$' 'info_cs_obsoletemethods.txt' "$CS_FILELIST"
do_filelist_grep 'hhmmss' 'bug_cs_invalidtimeformat.txt' "$CS_FILELIST"
#endregion


#region C problems
# c - (length or size).*(ntoh).* (minus or plus or times)
echo 
info "Starting C specific checks"
do_filelist_grep 'sprintf\s*\(.*\"[^\"]*%s.{0,99}$' 'bug_c_sprintf.txt' "$C_FILELIST"
do_filelist_grep 'sprintf\s*\(.*\"[^\"]*%ls.{0,99}$' 'bug_c_sprintf_ls.txt' "$C_FILELIST"
do_filelist_grep 'sscanf\s*\(.*\"[^\"]*%s.{0,99}$' 'bug_c_sscanf.txt' "$C_FILELIST"
do_filelist_grep 'fscanf\s*\(.*\"[^\"]*%s.{0,99}$' 'bug_c_fscanf.txt' "$C_FILELIST"
do_filelist_grep 'scanf\s*\(.*\"[^\"]*%s.{0,99}$' 'bug_c_scanf.txt' "$C_FILELIST"
do_filelist_grep '(length|size).*ntoh.*(-|\+|\*)' 'bug_c_ntoh_length_wrap.txt' "$C_FILELIST"
do_filelist_grep '(strlcpy|strlcat|strncpy|strncat|strcpy_s|strcat_s)\s*\(\s*\s*[^,]+\s*,\s*([^,]+)\s*,\s*(strlen|sizeof)\s*\(\s*\2\s*\)' 'bug-c-cpy-sizeof-src.txt' "$C_FILELIST"
do_filelist_grep '(strlcpy|strlcat|strncpy|strncat|strcpy_s|strcat_s)\s*\(\s*\s*[^,]+\s*,\s*([^,]+)\s*,\s*(strlen|sizeof)\s*\2\W' 'bug-c-cpy-sizeof-src2.txt' "$C_FILELIST"
do_filelist_grep '(strlcpy|strlcat|strncpy|strncat|strcpy_s|strcat_s)\s*\(\s*(\([^\)]*\))\s*[^,]+\s*,\s*([^,]+)\s*,\s*(strlen|sizeof)\s*(\()?\s*\3\s*(\))?' 'bug-c-cpy-sizeof-src3.txt' "$C_FILELIST"
do_filelist_grep 'memset\s*\([^,]*,[^,]*,\s*0\s*\).{0,99}$' 'bug_c_memset_zero_bytes.txt' "$C_FILELIST"
do_filelist_grep '(recv|Recv|recvfrom|recvmsg|RecvFrom)\(' 'info-arch_c_recv.txt' "$C_FILELIST"
do_filelist_grep 'socket\(' 'info_c_socket.txt' "$C_FILELIST"
do_filelist_grep 'k?malloc\(.*([+*]|-[^>])' 'info_c_malloc_wraparound.txt' "$C_FILELIST"
do_filelist_grep 'memcpy\(.*([+*]|-[^>])' 'info-c-memcpy-wraparound.txt' "$C_FILELIST"
do_filelist_grep 'memset\s*\([^,]*,\s*0\s*.{0,99}$' 'info-c-memset-insecure-zeroing.txt' "$C_FILELIST"
do_filelist_grep '(f|s|vf|v|vs)\?scanf\s*\(.{0,99}$' 'bug_c_scanf.txt' "$C_FILELIST"
do_filelist_grep '(f|s|vf|v|vs)\?scanf\s*\(.*\"[^\"]*%s.{0,99}$' 'bug_c_scanf_s.txt' "$C_FILELIST"
do_filelist_grep 'sprintf.*\%\.\*s.{0,99}sizeof.{0,99}$' 'bug_fmt_off_by_one.txt' "$C_FILELIST"
do_filelist_grep 'sprintf.*\%\.\*s.{0,200}$' 'info_potential_fmt_off_by_one.txt' "$C_FILELIST"

# Non-constant format specifiers (format string bugs)
do_filelist_grep '(printf|vprintf)\s*\([^",]+,[^",]+,' 'info-non-const-fmt-p1.txt' "$C_FILELIST"
do_filelist_grep '(f|s|as|d|vf|vs|vas|vd)printf\s*\([^",]+,[^",]+,' 'info-non-const-fmt-p2.txt' "$C_FILELIST"
do_filelist_grep '(sn|vsn)printf\s*\([^",]+,[^",]+,[^",]+,' 'info-non-const-fmt-p3.txt' "$C_FILELIST"
do_filelist_grep '\+=\s*v?snprintf.{0,99}$' 'bug_snprintf_retval_use.txt' "$C_FILELIST"
do_filelist_grep '#pragma\s+warning\s*\(\s*suppress' 'info_warning_supress.txt' "$C_FILELIST"
do_filelist_grep 's.?printf\(.{0,99}(/%s|%s/).{0,99}$' 'info_sprintf_path.txt' "$C_FILELIST"
do_filelist_grep 'len\s*=.*\*.{0,199}$' 'bug_trusted_length_in_input.txt' "$C_FILELIST"
#endregion

#region New rules, uncategorised
echo 
info "Starting general analysis ..."
do_filelist_grep '# <?= $token ?>.{0,200}$' 'bug_php_xss_interp.txt' "$PHP_FILELIST"
do_filelist_grep '<\w+>.*\$\w+.{0,200}$' 'bug_php_xss_tag.txt' "$PHP_FILELIST"
do_grep '\s+WHERE\s+[^\n]*\$\w+.{0,99}$' 'bug_sqli_where.txt'
do_grep '^[^\n]{0,99}\$\w+[^\n]{0,99}\s+(AND|OR)\s+[^\n]{0,99}\sIN\s*\([^\n]{0,99}\.[^\n]{0,99}\$\w+[^\n]{0,99}\)[^\n]{0,99}$' "" 'bug_php_sqli_in.txt'

do_grep 'http(s)?://\d+\.\d+\.\d+\.\d+.{0,200}$' 'bug_url_numeric.txt' "" "grep -v '127.0.0.1'"
do_grep '\WCVE-\d\d\d\d-.{0,200}$' 'info_cve_id.txt'
do_grep '\<in\>.{0,199}strings\.Join\(.{0,199}' 'bug_sqli_in_joined_strings.txt'
do_grep 'strings\.Join\(.{0,199}'\''.{0,199}$' 'bug_sqli_joined_strings_sgl.txt'
do_grep 'url-pattern{0,200}$' 'info-url-pattern.txt'
do_grep 'intercept-url{0,200}$' 'info-intercept-url.txt'
do_grep '[\s"'\''^\(\{\[]root/[a-zA-Z0-9\.\-\_\!\?\#\&\*\:\;\@\(\)\<\>\%]{12,}' 'bug_rootpwd.txt'

do_grep '@Controller.{0,200}$' 'info_routing_controller.txt'
do_grep '\W(asan|address_sanitizer|no_sanitize_address)\W.{0,200}$' 'info_asan_reference.txt' "-i"
do_grep '\W(segvs|segv|sigsegv)\W.{0,200}$' 'info_segv_reference.txt' "-i"
do_grep 'boost::process::child.{0,200}$' 'info_boost_process.txt'
do_grep 'mongodb://.{0,200}$' 'info_mongodb_url.txt'

do_filelist_grep 'len\s*=.*\*.{0,199}$' 'bug_trusted_length_in_input.txt' "$C_FILELIST" 
do_filelist_grep 'WERKZEUG_DEBUG_PIN.{0,200}$' 'bug_workzeug_debugger_active.txt' "$PYTHON_FILELIST"
do_filelist_grep '"[^"]*-[^"]\{[^"]*"\.format.{0,99}$' 'info_python_format_cmdi.txt' "$PYTHON_FILELIST"
do_grep 'obfusc.{0,200}$' 'info_obfuscation.txt'
do_grep 'FMemory::' 'info_unreal_mem.txt'
do_grep 'FPaths::' 'info_unreal_paths.txt'
do_grep 'FFileHelper::' 'info_unreal_fs.txt'
do_grep 'FModuleManager::' 'info_unreal_module.txt'
do_grep '^[^$"\n]*"[^$"\n]*/[^$"\n]*".{0,99}$' 'info_paths.txt'
do_grep '^.{0,200}\bnetsh\b.{0,200}$' 'info_netsh.txt'

do_grep 'SQLite format 3' 'info_sqlite3_files.txt' '-ial'
do_grep 'do\s+shell\s+script.{0,199}$' 'bug_applescript_shell.txt'
do_grep 'RpcServerRegisterIf.{0,199}$' 'info_rpc_reg.txt'
do_grep 'FltCreateCommunicationPort.{0,199}$' 'info_win_filter_drv_reg.txt'
do_grep '(NktHookLib|NKTHOOKLIB).{0,199}$' 'bug_nkt_hook_lib.txt'
do_grep 'ShellExecute.{0,199}$' 'info_cmdi_shellexec.txt'
do_grep '^.{0,199}(("[^\n"$-]*\s--[^-])|("--\w)).{0,199}$' 'info_cmdi_options.txt'
do_grep '\W(LoadLibrary|LoadLibraryA|LoadLibraryW|LoadLibraryEx|LoadLibraryExA|LoadLibraryExW)\([^/\n]{0,199}$' 'bug_insecure_loadlib.txt'
do_grep '\S{10,199}\.rds\.amazonaws\.com' 'bug_rds_hosts.txt'
do_grep '\S{10,199}\.amazonaws\.com.{0,199}$' 'bug_aws_hosts.txt'
do_grep 'require\(.{0,99}'\''\s*+.{0,99}$' 'bug_js_var_include.txt'
#endregion

echo 
info "Starting URL-based checks"
do_grep 'http://([a-zA-Z0-9]+\.)+[a-zA-Z0-9]+.{0,200}$' 'bug_insecure_url.txt' '' "grep -Pv ':\s*(\*+|//|/*|#|;)\s+' | grep -Pv ':\s*http://' | grep -Pvi '(readme|\.md|\.txt|xlmns|doctype)'"
do_grep '^.{0,200}http://.{0,200}$' 'bug_insecure_url2.txt' '' "grep -Pv ':\s*(\*+|//|/*|#|;)\s+' | grep -Pv ':\s*http://' | grep -Pvi '(readme|\.md|\.txt|xlmns|doctype)'"
do_grep 'https://([a-zA-Z0-9]+\.)+[a-zA-Z0-9]+.{0,200}$' 'info_secure_url.txt'
do_grep 's3://[^\.].{3,199}$' 'info_const_amazon_s3_url.txt'
do_grep 'https://s3-.{3,299}$' 'info_const_amazon_s3_url2.txt'

do_grep_return_uniq_token '\bF\w+::' 'info_unreal_FAPI.txt'
do_grep_return_uniq_token '\bU\w+::' 'info_unreal_UAPI.txt'

do_grep 'SimpleDB.{0,99}$' 'info_simpleDB.txt' '-i'
do_grep '\.SelectRequest.{0,99}$' 'bug_sqli_simpleDBSelect.txt' '-i'
do_filelist_grep '"[\s\(]*\b(select|insert|update|delete)\b.{0,199}"\s*\+\s*\w+.{0,99}$' 'bug_sqli_java_concat.txt' "$JAVA_FILELIST"

# Weak Randomness
echo 
info "Starting weak randomnness checks"
do_grep '\W(CryptGenRandom)\W.{0,99}$' 'info_rand_windows_good.txt'
do_grep '\W(System\.Random).{0,99}$' 'bug_rand_net_random.txt'
do_grep '\WMath\.random\(\W.{0,99}$' 'bug_rand_math_random.txt'
do_grep '\Wnew\sRandom\(\W.{0,99}$' 'bug_rand_new_random.txt'
do_grep '\Wrand\(\W.{0,99}$' 'bug_rand_rand.txt'
do_grep '\Wrandom\(\W.{0,99}$' 'bug_rand_random.txt'
do_grep '\Wutil\.Random\W.{0,99}$' 'bug_rand_util_random.txt'
do_grep '\W(ftime|gettimeofday|GetTickCount|GetTickCount64|QueryPerformanceCounter|GetSystemTime|GetLocalTime|GetSystemTimeAsFileTime|NtQuerySystemTime|time|uniqid|microtime)\(.{0,99}$' 'info_rand_time.txt'


# sqli
echo 
info "Starting SQL-related checks checks"
do_grep 'ExecuteStoredProcedure\(.{0,99}$' 'info_sqli_exec_sp.txt'
do_grep 'PQescapeString\(.{0,99}$' 'bug_sqli_deprecated_escape.txt'
do_grep 'mysql_escape_string\(.{0,99}$' 'bug_sqli_deprecated_escape2.txt'
do_grep 'grep -r \\.Where * | grep -v \=\>' 'info_sqli_where_dotnet.txt' "$CS_FILES"
do_grep '"select\s.{1,200}%s.{0,99}$' 'bug_sqli_c.txt'
do_grep '("|'\'')(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TRUNCATE|USE)\s.*%(s|r).*("|'\'').{0,99}$' 'bug_sqli_percent_interpolation.txt'
do_grep '("|'\'')(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TRUNCATE|USE)\s.*\$.*("|'\'').{0,99}$' 'bug_sqli_dollar_interpolation.txt'
do_grep '("|'\'')(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TRUNCATE|USE)\s.*{\d+}.*("|'\'').{0,99}$' 'bug_sqli_brace_interpolation.txt'
do_filelist_grep '\.(executeQuery|executequery|executeUpdate).{0,99}$' 'info_sqli_java_sqli.txt' "$JAVA_FILELIST" 
do_filelist_grep '\.execute\(\s*".{0,99}\%s.{0,99}$' 'bug_sqli_py_interp.txt' "$PYTHON_FILELIST"
do_filelist_grep '\.Select\(.{0,99}$' 'info_sqli_go_select.txt' "$GO_FILELIST"
do_filelist_grep '"database/sql"' 'info_sqli_go_sqlmodule.txt' "$GO_FILELIST"
do_grep '\W(exec\ssp_|exec\sxp_).{0,99}$' 'info_sqli_sp_xp.txt'
do_grep '\W(OleDbConnection|ADODB\.|System\.Data\.Sql|\.ResultSet).{0,99}$' 'info_sqli_sql_apis.txt' '--exclude=*.config'
do_grep '\Wexecute\s+immediate\W.{0,99}$' 'bug_sqli_oracle_execute_immediate.txt'
do_grep '\WEXECUTE\W.{0,99}$' 'info_sqli_sql_execute.txt'
do_grep '\Winsert\s+into\s+[a-zA-z0-9\.,\*].{0,99}$' 'info_sqli_insert.txt'
do_grep '\WPartialView\(.{0,99}$' 'info_sqli_partial_view.txt'
do_grep '\Wselect\W.{0,99}\Wfrom\W.{0,99}$' 'info_sqli_select_from.txt'
do_grep '\Wselect\s+[a-zA-z0-9\.,\*]+\s+from.{1,80}{\d+}.{0,99}$' 'bug_sqli_dotnet_interpolation2.txt'
do_grep '\Wsp_executesql\W.{0,99}$' 'bug_sqli_sp_executesql.txt'
do_grep 'CompileSelectWhere.{0,99}$' 'bug_sqli_compileSelectWhere.txt'
do_grep 'createSQLQuery.{0,99}$' 'info_sqli_createSQLQuery.txt'
do_grep 'dblink.{0,99}$' 'info_sqli_dblink.txt'
do_grep 'dbms_sql.execute.{0,99}$' 'bug_sqli_dbms_sql_exec.txt'
do_grep 'dbms_sql.parse.{0,99}$' 'bug_sqli_orcl_dbms_sql_parse.txt'
do_grep 'EXECUTE\s+IMMEDIATE.{0,99}$' 'bug_sqli_orcl_exec_immediate.txt'

do_filelist_grep 'import\s+java.sql.{0,99}$' 'info_sqli_import_java_sql.txt' "$JAVA_FILELIST" 
do_filelist_grep 'sql\.append\(.{0,99}$' 'bug_sqli_java_sqli_append.txt' "$JAVA_FILELIST" 

do_grep 'order\sby.{0,99}$' 'info_sqli_order_by.txt'
do_grep 'queryBuilder.{0,99}$' 'info_sqli_queryBuilder.txt'

do_grep 'sqlHelper.runQuery.{0,99}$' 'info_sqli_sqlHelper.txt'

# cmdi
echo 
info "Starting cmdi checks"
do_grep '^.{0,99}\Wexec\(.{0,99}$' 'info_cmdi_exec2.txt'
do_grep '^.{0,99}\Wspawn\(.{0,99}$' 'info_cmdi_spawn.txt'
do_grep '\"\w+\.exe\".{0,99}$' 'info_cmdi_exe_exec.txt'
do_grep 'os\.execute.{0,99}$' 'bug_cmdi_lua_exec.txt'
do_grep '\.StartInfo.{0,99}$' 'bug_cmdi_dotnet_process.txt'
do_grep '["'\''](chmod|chown|cmd.exe|copy|cp|git|gzip|mkdir|mktemp|rm|ssh|tar|unzip|/bin/sh|gunzip|del|cat|sed)\s.{0,199}$' 'info_cmdi_command.txt'
do_grep '\.!!.{0,99}$' 'info_cmdi_scala_cmd_bangbang.txt'
do_grep '\.![^!].{0,99}$' 'info_cmdi_scala_cmd_bang.txt'
do_grep 'ProcessBuilder\s*\(.{0,99}$' 'bug_cmdi_scala_processbuilder.txt'
do_grep '\Wsystem\("[^"]*\$.{0,99}$' 'bug_cmdi_perl_interp.txt'
do_grep '\Wsystem\("[^"]*@.{0,99}$' 'bug_cmdi_perl_interp2.txt'
do_grep '\Wsystem\([^)].{0,99}$' 'info_cmdi_system_noempty.txt'
do_grep '\Wcheck_output\([^)].{0,99}$' 'info_cmdi_check_output.txt'
do_grep 'child_process.{0,99}$' 'info_cmdi_child_process.txt'
do_grep '\WCreateProcess\W.{0,99}$' 'info_cmdi_createProcess.txt'
do_grep 'exec[lv][epP]*\(.{0,99}$' 'info_cmdi_c_process_exec.txt'
do_grep 'new\sProcess\(.{0,99}$' 'info_cmdi_process_new.txt'
do_grep 'popen\([^)].{0,99}$' 'info_cmdi_popen.txt'
do_grep '\WPopen\([^)].{0,99}$' 'info_cmdi_Popen2.txt'
do_grep 'ProcessStartInfo.{0,99}$' 'info_cmdi_win_proc_start.txt'
do_grep 'shell_exec.{0,99}$' 'info_cmdi_shell_exec.txt'
do_grep '\W\.exec.{0,99}$' 'info_cmdi_exec.txt'

# string interpolation
echo 
info "Starting string interpolation checks"
do_grep \''\s*\+.{0,99}\+\s*'\''.{0,99}$' 'info_str_plus.txt'
do_grep '\".{0,99}\$.{0,99}\".{0,99}$' 'info_str_interp_dollar.txt'
do_grep '\.mkString\(.{0,99}$' 'info_str_scala_mkString.txt'
do_grep '\$\".{0,99}{.{0,99}\".{0,99}$' 'info_str_interp_brace.txt'
do_grep '^.{0,99}'\"\''.{0,99}$' 'bug_str_mixed_quote_dbl.txt'
do_grep '^.{0,99}'\'\"'.{0,99}$' 'bug_str_mixed_quote_sgl.txt'
do_grep '\.Format.{1,80}\s-.{1,80}{\d+}.{0,99}$' 'info_str_dot_net.txt'
do_grep '\.Format.{1,80}\{\d+\}.{1,80}\s-.{1,80}.{0,99}$' 'info_str_dot_net2.txt'
do_grep 'string\.Join\(.{0,199}$' 'info_str_join.txt'

# Elevation
echo 
info "Starting *nix privesc checks"
do_grep 'chown\(.{0,199}$' 'info_priv_chown.txt'
do_grep 'chmod\(.{0,199}$' 'info_priv_chmod.txt'

# SSL Diabling
echo 
info "Starting SSL disablement checks"
do_grep 'curl.{0,99}\s-k\W.{0,99}$' 'bug_ssl_disable_curl.txt'
do_filelist_grep 'checkServerTrusted.{0,99}$' 'bug_ssl_disable_python.txt' "$PYTHON_FILELIST"
do_filelist_grep 'InsecureRequestWarning.{0,99}$' 'bug_ssl_disable_java.txt' "$JAVA_FILELIST"
do_filelist_grep 'ServerCertificateValidationCallback' 'bug_ssl_dotnet.txt' "$CS_FILELIST"   # Only a bug if its set to 'true'
do_filelist_grep 'no-check-cert.{0,99}$' 'bug_ssl_disable_python2.txt' "$PYTHON_FILELIST"
do_filelist_grep 'verify\s*=\s*False.{0,99}$' 'bug_ssl_disable_python3.txt' "$PYTHON_FILELIST"
do_grep 'StrictHostKeyChecking=no.{0,99}$' 'bug_ssh_disable_hostkey_check.txt'

# Web routing etc
echo 
info "Starting web routing analysis"
do_filelist_grep '\.add_resource\W.{0,200}$' 'info_routing_python.txt' "$PYTHON_FILELIST"
do_filelist_grep '\W(Application_OnAuthenticateRequest|Application_OnAuthorizeRequest|Session_OnStart).{0,99}$' 'info_web_net_events.txt' "$CS_FILELIST"
do_grep '\W(RequestMinimum|RequestOptional|SkipVerification|UnmanagedCode).{0,99}$' 'bug_web_sec_override.txt'
do_grep '\W(FileInputStream|FilterInputStream|SequenceInputStream|StringBufferInputStream|ByteArrayInputStream|FileOutputStream).{0,99}$' 'info_web_input.txt'
do_grep '\W(getRemoteAddr|getRemoteHost).{0,99}$' 'info_web_remote_name.txt'
do_grep '\W(getRealPath).{0,99}$' 'info_web_path.txt'
do_filelist_grep 'require\('\''fs'\''\).{0,99}$' 'info_py_filesystem.txt' "$PYTHON_FILELIST"
do_grep '/endpoints/.{0,99}$' 'info_endpoints.txt'
do_grep '\[Route\(.{0,99}$' 'info_routing_decorator.txt'
do_grep '\[RoutePrefix\(.{0,99}$' 'info_routing_decorator2.txt'
do_grep '\.route\(.{0,199}$' 'info_routing_web.txt'
do_grep '\WRequest\..{0,99}$' 'info_web_request_dot.txt'
do_grep 'Get\[.{0,99}$' 'info_routing_get.txt'
do_filelist_grep '@GET.{0,99}$' 'info_routing_java_get.txt' "$JAVA_FILELIST"
do_filelist_grep '@GetMapping.{0,99}$' 'info_routing_java_getmapping.txt' "$JAVA_FILELIST"
do_filelist_grep '@POST.{0,99}$' 'info_routing_java_post.txt' "$JAVA_FILELIST"
do_filelist_grep '@Path\(.{0,99}$' 'info_routing_java_path.txt' "$JAVA_FILELIST"
do_filelist_grep '@RequestMapping.{0,99}$' 'info_routing_java_requestmapping.txt' "$JAVA_FILELIST"
do_filelist_grep 'RequestMethod\.[A-Z]+.{0,99}$' 'info_routing_java_requestmethod.txt' "$JAVA_FILELIST"
do_grep '\badd_resource\b' 'info_routing_flask.txt'
do_grep '^.{0,99}\.get\(.{0,99}$' 'info_routing_node_get.txt'
do_grep '^.{0,99}\.put\(.{0,99}$' 'info_routing_node_put.txt'
do_grep '^.{0,99}\.post\(.{0,99}$' 'info_routing_node_post.txt'

# Web request handler
echo 
info "Starting SSL disablement checks"
do_filelist_grep '\.getHeader\(.{0,99}$' 'info_web_java_custom_header.txt' "$JAVA_FILELIST"
do_grep 'HttpServletRequest.{0,99}$' 'info_web_HttpServletRequest.txt'
do_filelist_grep 'HttpResponseMessage.{0,99}$' 'info_web_dotnet.txt' "$CS_FILELIST"

# deserialisation
echo 
info "Starting deserialization checks"
do_filelist_grep '\.readObject\(.{0,99}$' 'bug_java_deserialisation.txt'  "$JAVA_FILELIST"
do_filelist_grep 'pickle\.loads\(.{0,99}$' 'bug_python_deserialisation.txt' "$PYTHON_FILELIST"
do_filelist_grep 'pickle\.load\(.{0,99}$' 'bug_python_deserialisation2.txt' "$PYTHON_FILELIST"
do_filelist_grep '\.loads\(.{0,99}$' 'info_python_deserial.txt' "$PYTHON_FILELIST"

# File system
echo 
info "Starting file system interaction analysis"
do_grep 'FileStream.{0,99}$' 'info_file_Stream.txt'
do_grep '\WFile\.Copy\(.{0,99}$' 'info_file_copy.txt'
do_grep 'copyFile\(.{0,99}$' 'info_file_copyFile.txt'
do_grep 'File\..{0,99}$' 'info_file_dot.txt'
do_grep 'FileSystem\W.{0,99}$' 'info_fileSystem_call.txt'
do_grep 'MemoryMappedFile.{0,99}$' 'info_memoryMappedFile.txt'
do_grep 'new\sFile\(.{0,99}$' 'info_new_file.txt'
do_filelist_grep '\.SaveAs\(.{0,99}$' 'info_dotnet_saveas.txt' "$CS_FILELIST"
do_grep 'file_get_contents.{0,99}$' 'info_file_get_contents.txt'

# Crypto
echo 
info "Starting weak crypto analysis"
do_grep '[D|d]iffie.*[H|h]ellman.{0,99}$' 'info_crypto_diffie_hellman.txt'
do_grep 'AES\.DecryptFromBase64.{0,99}$' 'info_crypto_b64.txt'
do_grep 'AES\.DecryptFromBase64.{0,99}$' 'info_crypto_b64_2.txt'
do_grep '\W(AES|DES|SHA|SHA1|SHA2|SHA256|SHA512|blowfish|MD5|IDEA|RSA|DSA|MD4|SHA3|HMAC)\W.{0,99}$' 'info_crypto_algorithm_name.txt'
do_grep '\W(CryptAcquireContext|CryptDeriveKey|CryptGenKey|CryptGenRandom)\W.{0,99}$' 'info_crypto_api_call.txt'

# Windows API Areas
echo 
info "Starting Windows API analysis"
do_grep 'CreateEvent.{0,99}$' 'info_createEvent.txt'
do_grep 'dllimport.{0,99}$' 'info_dllimport.txt'
do_grep '(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG).{0,99}$' 'info_winreg_key.txt'
do_grep '(OpenSubKey|RegOpenKey|RegQueryInfoKey|RegQueryValue|RegSetValue).{0,99}$' 'info_winreg_api.txt'
do_filelist_grep 'string\.Format\(.*{.{0,99}$' 'info_dotnet_interpolation.txt' "$CS_FILELIST"
do_filelist_grep 'string\.Format.{0,99}$' 'info_dotnet_string_format.txt' "$CS_FILELIST"
do_filelist_grep 'System\.IO\.Pipes.{0,99}$' 'info_dotnet_pipes.txt' "$CS_FILELIST"
do_filelist_grep 'System\.Net.{0,99}$' 'info_dotnet_net.txt' "$CS_FILELIST"

#region Versions
echo 
info "Starting product versioning analysis"
do_grep 'AWS_JSONCPP_VERSION_STRING.{0,99}$' 'info_ver_jsoncpp.txt'
do_grep 'AWS_SDK_VERSION_STRING.{0,99}$' 'info_ver_aws_sdk.txt'
do_grep 'BZ_VERSION.{0,99}$' 'info_ver_bzip.txt'
do_grep 'JANSSON_VERSION.{0,99}$' 'info_ver_jansson.txt'
do_grep 'LIBCURL_VERSION.{0,99}$' 'info_ver_libcurl.txt'
do_grep 'MARIADB_PACKAGE_VERSION.{0,99}$' 'info_ver_mariadb.txt'
do_grep '(MDB_VERSION_MAJOR|MDB_VERSION_MINOR|MDB_VERSION_PATCH).{0,99}$' 'info_ver_mdb.txt'
do_grep 'MONGOOSE_VERSION.{0,99}$' 'info_ver_mongoose.txt'
do_grep 'OPENSSL_VERSION_TEXT.{0,99}$' 'info_ver_openssl.txt'
do_grep '(PG_MAJORVERSION|PG_VERSION|PG_VERSION_STR).{0,99}$' 'info_ver_postgres.txt'
do_grep 'SQLITE_VERSION.{0,99}$' 'info_ver_sqlite.txt'
do_grep 'U_ICU_VERSION.{0,99}$' 'info_ver_u_icu.txt'
do_grep 'ZLIB_VERSION.{0,99}$' 'info_ver_zlib.txt'
#endregion

#region Dangerous HTTP patterns
echo 
info "Starting dangerous HTTP routing analysis"
do_grep 'HTTP_USER_AGENT.{0,99}$' 'info_http_user_agent.txt'
do_grep 'HTTP_X_FORWARDED_FOR.{0,99}$' 'info_http_x_forwarded_for.txt'
#endregion

#region Interesting comments
echo 
info "Starting interesting comments analysis"
do_grep '\W(TODO|HACK|FIXME|XXX|BROKEN|BUG)\W.{0,99}$' 'info_comment_todos.txt' '-io'
# Please note we are looking for offensive terms here; please don't be offended by our attempt to find offensive words...!
do_grep '\W(as\x73hole|ba\x73tard|brain\x66uck|co\x63k|cr\x61p|cr\x61ppy|cu\x6et|di\x63k|flippin|flipping|fu\x63k|fu\x63king|mother\x66ucker|s\x63rewed|s\x68it|pu\x73sy|t\x69ts)\W.{0,99}$' 'info_comment_obscenities.txt' '-io'
do_grep 'NOLINT|noinspection|safesql|coverity|fortify|veracode|DevSkim|checkmarx|sonarqube|\Wnosec\W.{0,99}$' 'info_comment_static_analysis_tool.txt'
do_grep 'rubocop:disable.{0,99}$' 'info_comment_rubocop_disable.txt'
do_grep 'rubocop:disable\s+Security.{0,99}$' 'bug_comment_rubocop_disable_security.txt'
do_grep 'inflate.*[0123456789.]{3,}.*Copyright.*Mark.*Adler.{0,99}$' 'info_comment_inflate_version.txt'
do_grep 'credit.card.{0,99}$' 'info_comment_credit_card.txt'
do_grep '\Wcvv\W.{0,99}$' 'info_comment_cvv.txt'
do_grep '\Wlucky*\W' 'info_comment_luck.txt'
do_grep 'security (concern|problem|vulnerability|issue).{0,199}$' 'info_comment_security_concern.txt'
#endregion

#region Interesting constants / unique tokens
echo 
info "Starting interesting constants / unique tokens analysis"
do_grep_return_uniq_token '^\s*require\s+"[^"]+"\s*$' 'info_uniq_sorted_ruby_requires.txt'
do_grep_return_uniq_token 'DynamoDBTable' 'info_uniq_sorted_dynamo_db_tables.txt'
do_grep_return_uniq_token '(^|[^A-Z0-9])(AKIA|ASIA)[A-Z0-9]{16}($|[^A-Z0-9])' 'info_uniq_sorted_amazon_access_ids.txt'
do_grep_return_uniq_token "$domainName" 'info_uniq_sorted_hosts.txt'
do_grep_return_uniq_token "$emailAtDomain" 'info_uniq_sorted_emails.txt'
do_grep_return_uniq_token '['\''"]([1-2]?[0-9]?[0-9]\.){3}([1-2]?[0-9]?[0-9])['\''"]' 'info_uniq_sorted_ip_addresses.txt'
do_grep_return_uniq_token '[a-zA-Z0-9_]+\(' 'info_uniq_sorted_fn_calls.txt'
do_grep_return_uniq_token 'require\('\''.{0,32}\)' 'info_uniq_sorted_requires.txt'
do_grep_return_uniq_token 'require\('\''[\a-zA-Z0-9_/.]*\)' 'info_uniq_sorted_requires2.txt'
do_grep_return_uniq_token 'https?://[^'\''"\s\n]*' 'info_uniq_sorted_urls.txt'
do_grep_return_uniq_token 'https://s3-[^'\''"\n]*' 'info_uniq_sorted_s3_urls.txt'
do_grep_return_uniq_token 's3://[^/'\''"\n]+' 'info_uniq_sorted_s3_buckets.txt'
do_grep_return_uniq_token '[a-zA-Z0-9_\.]{0,99}(/[a-zA-Z0-9_\.]{1,99}){1,99}/?' 'info_uniq_sorted_paths.txt'
do_grep_return_uniq_token '\S{10,199}\.amazonaws\.com' 'info_uniq_sorted_aws_hosts.txt'
do_grep_return_uniq_token '^.{0,8}copyright.{0,199}$' 'info_uniq_sorted_copyright_notices.txt'

do_grep '[a-f0-9-]{16,}.{0,99}$' 'info_const_hex.txt' '' "grep -Pvi '([0-9a-f-])\1{4,}'"
do_grep '[a-f0-9]{16,}.{0,99}$' 'info_const_hex2.txt' '' "grep -Pvi '([0-9a-f])\1{4,}'"
#endregion

#region Creds in code
# Do cred checks last
do_grep '<bcrypt-hash>.{0,199}$' 'bug_bcrypt_hash.txt'

do_grep '(^|[^A-Z0-9])(AKIA|ASIA)[A-Z0-9]{16}($|[^A-Z0-9]).{0,99}$' 'bug_const_amazon_access_id2.txt'
do_grep '(accesskey|secretkey|apisecret|apikey|GSUsername|GSPassword|SteamBuildMachineUsername|SteamBuildMachinePassword|S3BucketName).{0,99}[=:].{0,99}$' 'info-creds-secretname-equals.txt'
do_grep '^.{0,299}x-access-token.{0,299}$' 'info_creds_access_token.txt'
do_grep '^(.{0,10})export .{0,99}(LOGIN|USER|KEY|SECRET|BUCKET|TOKEN|CREDS|CREDENTIAL|PASS|AUTH).{0,99}=[^$]{6,199}$' 'bug_export_creds.txt'
do_grep 'insecure-password.{0,99}$' 'bug_haproxy-plaintext-password.txt'
do_grep '["'\''][A-Z0-9]{20}["'\''].{0,99}$' 'info_const_amazon_access_id.txt'
do_grep '["'\''][A-Za-z0-9/+=]{40}["'\''].{0,99}$' 'info_const_amazon_secret_key.txt'

do_grep '^.{0,99}#define.{0,99}PASSWORD.{0,99}".{0,99}$' 'bug_define_password.txt'
do_grep '\w+://\w+:\w+@\w+.{0,99}$' 'bug_creds_in_url.txt'
do_grep '^.{0,200}curl[^\n]{0,200}-u[^\n]{0,200}:[^\n]{0,200}$' 'cred_curl_auth.txt'

do_grep '^.{0,199}"[a-f0-9]{16,}".{0,199}$' 'info-creds-hex-dblquotes.txt'
do_grep '^[^=\n]{0,199}TOKEN[^=\n]{0,30}=\s*[^\n\s]{7,199}\s*$' 'info-cred-token-equals.txt'
do_grep '^[^=\n]{0,199}KEY[^=\n]{0,30}=\s*[^\n\s]{7,199}\s*$' 'info-cred-key-equals.txt'
do_grep '^[^=\n]{0,199}API_KEY[^\n]{7,199}$' 'info-api_key.txt'
do_grep '^[^=\n]{0,199}SECRET[^=\n]{0,30}=\s*[^\n\s]{7,199}\s*$' 'info-cred-secret-equals.txt'
do_grep '^[^=\n]{0,199}PASSWORD[^=\n]{0,30}=\s*[^\n\s]{7,199}\s*$' 'info-cred-password-equals.txt'
do_grep 'GITHUB_TOKEN.{0,299}$' 'bug_cred_github_token.txt'
do_grep '[A-Z0-9]{1..99}_SECRET[A-Z0-9_]*.{0,99}$' 'bug_CAPS_secret.txt'
do_grep '(AWSSecretKey|AwsDevSecretKey|SecretKey|ClientSecret|BasicAWSCredentials|clientSecret|AWS_SECRET_KEY|AgentToken).{0,199}$' 'bug_aws_secret_key.txt'
do_grep '(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_DEFAULT_REGION).{0,199}$' 'bug_aws_creds.txt'
do_grep '"jdbc:\w+://[^"]{0,99}".{0,99}$' 'bug_cred_jdbc_dbl.txt'
do_grep '\s--password\s*=\s*[^\$\%].{0,99}$' 'bug_cred_password01.txt'
do_grep '\Wmysql\s.{0,99}[^-]-p[^\$\%].{0,99}$' 'bug_cred_mysql_passwords.txt'
do_grep '^\s*password\s\S{5,99}\s*$' 'bug_cred_password_config.txt'
do_grep 'new mysqli\(.{0,99}$' 'bug_cred_mysql_connect_call.txt'
do_grep '\-----BEGIN[A-Z\s]*KEY[A-Z\s]*-----' 'info_cred_keys.txt'
do_grep '^[.a-zA-Z0-9_-]+(:[.a-zA-Z0-9_-]+){4}$' 'bug_cred_postgres_pgpass_format.txt'
do_grep 'Authorization:\s*Basic\s.{0,99}$' 'info_basic_auth.txt'
do_grep 'Authorization:\s*\w+\s*[A-Za-z0-9.+=_@!^&*()-?]{8,200}\W' 'bug_cred_auth_header.txt'
do_grep 'base64.{0,99}$' 'info_cred_base64.txt'
do_grep 'IDENTIFIED\s+BY\s+'\''[^\n]{0,299}$' 'info_cred_identified_by.txt'
do_grep 'ConnectionString\s*=.{0,99}$' 'info_cred_connectionString.txt'
do_grep '(DSN|DATASOURCE|UID|USER\sID|USER)=[^;].{1,99}(PASSWORD|PWD)=[^;].{1,99}$' 'bug_cred_connectionstring2.txt'
do_grep 'password\s*=\s*".{0,99}$' 'info_cred_password_equals.txt'
do_grep 'password[^=\n]{0,30}=.{0,199}$' 'bug_cred_password_equals.txt'
do_grep 'password=[^\s";.]*.{0,199}$' 'bug_cred_password02.txt'
do_grep 'password"[^"]*value="[^"]*.{0,199}$' 'bug_cred_password03.txt'
do_grep 'password"[^",\w]{0,50}"[^"]{0,50}".{0,199}$' 'bug_cred_password04.txt'
do_grep 'key=[^\s";.]*.{0,199}$' 'bug_cred_password05.txt'

do_grep 'privateKey.{0,99}$' 'info_cred_private_key.txt'
do_grep 'publicKey.{0,99}$' 'info_cred_public_key.txt'
do_grep '\.SecretKey.{0,99}$' 'info_cred_dot_secret_key.txt'
do_grep \''jdbc:\w+://[^'\'']{0,99}'\''.{0,99}$' 'bug_cred_jdbc_sgl.txt'
do_grep '<Password>.{5,200}</Password>' 'bug_cred_buildfile.txt'
do_grep '(?i)github[^=]*=[^=]*[0-9a-zA-Z]{35,40}.{0,99}$' 'bug_cred_github.txt'
do_grep '(?i)facebook[^=]*=[^=]*[0-9a-f]{32}.{0,99}$' 'bug_cred_facebook.txt'
do_grep '(?i)twitter[^=]*=[^=]*[0-9a-zA-Z]{35,44}.{0,99}$' 'bug_cred_twitter.txt'
do_grep '(?i)telegram[^=]*=[^=]*[0-9]{1,12}+:[0-9a-zA-Z-]{32,44}.{0,99}$' 'bug_cred_telegram.txt'
do_grep 'xox[baprs]-[^=]*=[^=]*.{0,99}$' 'bug_cred_slack.txt'
do_grep '(?i)(sk|pk)_(test|live)_[0-9a-zA-Z]{10,32}.{0,99}$' 'bug_cred_strip_token.txt'
do_grep 'signtool.*/p.{0,99}$' 'bug_cred_signtool_password.txt'
#endregion

#region Common hash formats
do_grep '0x01[0-9a-zA-Z]{50}\W.{0,99}$' 'hash_MSSQL-2005.txt'
do_grep '0x01[0-9a-zA-Z]{90}\W.{0,99}$' 'hash_MSSQL-2000.txt'
do_grep '0x02[0-9a-zA-Z]{138}\W.{0,99}$' 'hash_MSSQL-2012-2014.txt'
do_grep '0x[0-9a-zA-Z]{60}\W.{0,99}$' 'hash_EPi.txt'
do_grep '0x[0-9a-zA-Z]{84}\W.{0,99}$' 'hash_SybaseASE.txt'
do_grep '\$1\$\w{4,99}$\w{4,99}.{0,99}$' 'bug_cred_hash_1.txt'
do_grep '\$2\w\$\d+\$[A-Za-z0-9./]{20,}.{0,99}$' 'bug_cred_hash_2x.txt'
do_grep '\$2a\$05\$.{0,99}$' 'bug_cred_hash_2.txt'
do_grep '\$5\$\w{4,99}$\w{4,99}.{0,99}$' 'bug_cred_hash_3.txt'
do_grep '\$6\$\w{4,99}$\w{4,99}.{0,99}$' 'bug_cred_hash_4.txt'
do_grep '\$8\$\w{4,99}$\w{4,99}.{0,99}$' 'bug_cred_hash_5.txt'
do_grep '\$9\$\w{4,99}$\w{4,99}.{0,99}$' 'bug_cred_hash_6.txt'
do_grep '\$apr1\$\w{4,99}$\w{4,99}.{0,99}$' 'bug_cred_hash_7.txt'
do_grep '\$DCC2\$\d+#.*#.{0,99}$' 'bug_cred_hash_8.txt'
do_grep '\$keepass\$\*\d+\*\d+\*\d+\*.{0,99}$' 'bug_cred_hash_9.txt'
do_grep '\$krb5tgs\$23\$.{0,99}$' 'bug_cred_hash_10.txt'
do_grep '\$md5\$.*\$.{0,99}$' 'bug_cred_hash_11.txt'
do_grep '\$ml\$\d+\$.{0,99}$' 'bug_cred_hash_12.txt'
do_grep '\$office\$\*2007\*.{0,99}$' 'bug_cred_hash_13.txt'
do_grep '\$office\$\*2010\*.{0,99}$' 'bug_cred_hash_14.txt'
do_grep '\$office\$\*2013\*.{0,99}$' 'bug_cred_hash_15.txt'
do_grep '\$oldoffice\$1\*\d+.{0,99}$' 'bug_cred_hash_16.txt'
do_grep '\$S\$.{0,99}$' 'bug_cred_hash_17.txt'
do_grep '\W[0-9a-fA-F]{128}:[0-9a-fA-F]{10}\W.{0,99}$' 'hash_saltedsha512.txt'
do_grep '\W[0-9a-fA-F]{128}:[0-9a-fA-F]{64}\W.{0,99}$' 'hash_FileZillaServer-0.9.55.txt'
do_grep '\W[0-9a-fA-F]{128}\W.{0,99}$' 'hash_SHA-512.txt'
do_grep '\W[0-9a-fA-F]{130}:[0-9a-fA-F]{40}\W.{0,99}$' 'hash_IPMI2-RAKP-HMAC-SHA1.txt'
do_grep '\W[0-9a-fA-F]{136}\W.{0,99}$' 'hash_OSXv10.7.txt'
do_grep '\W[0-9a-fA-F]{160}\W.{0,99}$' 'hash_Android-FDE-SamsungDEK.txt'
do_grep '\W[0-9a-fA-F]{160}\W.{0,99}$' 'hash_Oracle12.txt'
do_grep '\W[0-9a-fA-F]{16}:[0-9a-fA-F]{10}\W.{0,99}$' 'hash_DES-Oracle.txt'
do_grep '\W[0-9a-fA-F]{16}:[0-9a-fA-F]{32}\W.{0,99}$' 'hash_SipHash.txt'
do_grep '\W[0-9a-fA-F]{16}\W.{0,99}$' 'hash_MySQL323.txt'
do_grep '\W[0-9a-fA-F]{32}:[0-9a-fA-F]{13}\W.{0,99}$' 'hash_DomainCachedCredentials.txt'
do_grep '\W[0-9a-fA-F]{32}:[0-9a-fA-F]{2,20}\W.{0,99}$' 'hash_salted_md5.txt'
do_grep '\W[0-9a-fA-F]{32}:[0-9a-fA-F]{2,20}\W.{0,99}$' 'hash_IPB2.txt.txt'
do_grep '\W[0-9a-fA-F]{32}:[0-9a-fA-F]{30}\W.{0,99}$' 'hash_vBulletin.txt'
do_grep '\W[0-9a-fA-F]{32}:[0-9a-fA-F]{32}\W.{0,99}$' 'hash_Joomla.txt'
do_grep '\W[0-9a-fA-F]{32}[^:0-9a-fA-F].{0,99}$' 'hash_Radmin2.txt'
do_grep '\W[0-9a-fA-F]{32}\W.{0,99}$' 'hash_md4_md5.txt'
do_grep '\W[0-9a-fA-F]{40}:[0-9a-fA-F]{126}\W.{0,99}$' 'hash_PeopleSoft.txt'
do_grep '\W[0-9a-fA-F]{40}:[0-9a-fA-F]{12}\W.{0,99}$' 'hash_PunBB.txt'
do_grep '\W[0-9a-fA-F]{40}:[0-9a-fA-F]{16}\W.{0,99}$' 'hash_SamsungAndroidPassword.txt'
do_grep '\W[0-9a-fA-F]{40}:[0-9a-fA-F]{2,20}\W.{0,99}$' 'hash_salted_sha1.txt'
do_grep '\W[0-9a-fA-F]{40}:[0-9a-fA-F]{20}\W.{0,99}$' 'hash_Oracle11.txt'
do_grep '\W[0-9a-fA-F]{40}:[0-9a-fA-F]{32}\W.{0,99}$' 'hash_Redmine.txt'
do_grep '\W[0-9a-fA-F]{40}:[0-9a-fA-F]{9}\W.{0,99}$' 'hash_OpenCart.txt'
do_grep '\W[0-9a-fA-F]{40}\W.{0,99}$' 'hash_sha1.txt'
do_grep '\W[0-9a-fA-F]{48}\W.{0,99}$' 'hash_OSX.txt'
do_grep '\W[0-9a-fA-F]{49}\W.{0,99}$' 'hash_CitrixNetScaler.txt'
do_grep '\W[0-9a-fA-F]{50}\W.{0,99}$' 'hash_ArubaOS.txt'
do_grep '\W[0-9a-fA-F]{56}\W.{0,99}$' 'hash_SHA-224.txt'
do_grep '\W[0-9a-fA-F]{64}:[0-9a-fA-F]{256}\W.{0,99}$' 'hash_WindowsPhone8.txt'
do_grep '\W[0-9a-fA-F]{64}:[0-9a-fA-F]{64}\W.{0,99}$' 'hash_ColdFusion.txt'
do_grep '\W[0-9a-fA-F]{64}:[0-9a-fA-F]{8}\W.{0,99}$' 'hash_HMAC-SHA256.txt'
do_grep '\W[0-9a-fA-F]{64}\W.{0,99}$' 'hash_SHA-256.txt'
do_grep '\W[0-9a-fA-F]{70}\W.{0,99}$' 'hash_hMailServer.txt'
do_grep '\W[0-9a-fA-F]{96}\W.{0,99}$' 'hash_SHA-384.txt'
do_grep 'password\s+[0-9a-zA-Z\+\.\/]{16}\s+encrypted.{0,99}$' 'hash_Cisco-PIX-MD5.txt'
do_grep '\W[0-9a-zA-Z\+\.\/]{46}=\W.{0,99}$' 'hash_FortiGate.txt'
#do_grep '\W[0-9a-zA-Z\.\-\+\$\/]{20}[^0-9a-zA-Z\.\-\+\$\/]' 'hash_JWT.txt'
#do_grep '\W[0-9a-zA-Z]{10}[^0-9a-zA-Z]\W' 'hash_Tripcode.txt'
do_grep '\W[0-9a-zA-Z]{27}=.{0,99}$' 'hash_PeopleSoft.txt'
do_grep '\W[0-9a-zA-Z]{32}:[0-9a-zA-Z]{2,20}\W.{0,99}$' 'hash_PostgreSQL.txt'
do_grep '\W[0-9a-zA-Z]{43}\W.{0,99}$' 'hash_Cisco-IOS-type-4.txt'
do_grep '\W[0-9a-zA-Z]{48}:[0-9a-zA-Z]{16}\W.{0,99}$' 'hash_NetNTLMv1.txt'
do_grep '\W[a-f0-9]{128}:\w+\W.{0,99}$' 'bug_cred_hash_19.txt'
do_grep '\W[a-f0-9]{32}:\w+\W.{0,99}$' 'bug_cred_hash_21.txt'
do_grep '\W[a-f0-9]{40}:\w+\W.{0,99}$' 'bug_cred_hash_23.txt'
do_grep '\W[a-f0-9]{64}:\w+\W.{0,99}$' 'bug_cred_hash_25.txt'
do_grep '\W\w+:\d+:[a-f0-9]{32}:[a-f0-9]{32}\W.{0,99}$' 'bug_cred_hash_27.txt'
do_grep '\W\w+\$[a-f0-9]{16}\W.{0,99}$' 'bug_cred_hash_26.txt'
do_grep '\{PKCS5S2\}[0-9a-zA-Z]{64}\W.{0,99}$' 'hash_Atlassian.txt'
do_grep '\{ssha256\}[0-9a-zA-Z\$\+\/\.]{20,}\W.{0,99}$' 'hash_AIX.txt'
do_grep '\{SSHA256\}[0-9a-zA-Z\+\/]{47}\W.{0,99}$' 'hash_SSHA-256.txt'
do_grep '\{ssha512\}[0-9a-zA-Z\$\.\-\+\/]{20,}\W.{0,99}$' 'hash_AIX.txt'
do_grep '\{SSHA512\}[0-9a-zA-Z\+]{95}\W.{0,99}$' 'hash_SSHA-512.txt'
do_grep 'md5\$.{0,99}\$[a-zA-Z0-9].{0,99}$' 'bug_cred_hash_md5.txt'
do_grep 'u4-netntlm::.{0,99}$' 'bug_cred_hash_28.txt'
do_grep '\{ssha1\}06\$.*\$.{0,99}$' 'bug_cred_hash_29.txt'
do_grep '\{ssha256\}06\$.{0,199}$' 'bug_cred_hash_30.txt'
do_grep '\{SSHA512\}.{0,199}$' 'bug_cred_hash_31.txt'
do_grep '\{ssha512\}06\$.{0,199}$' 'bug_cred_hash_32.txt'
do_grep '\{x-issha,\s*1024\}.{0,199}$' 'bug_cred_hash_33.txt'
#endregion

echo 
info "Custom greps finished"

echo 
info "Starting banned function greps - this may take a while"

do_fast_banned_grep

# Rule( 'jdbc', 'password', 'jdbc:(\w+:)+//.{,80}(password|pwd)\s*=(?P<pwd>\S+)', [] ),
# Rule( 'password', 'password', 'password\s*=\s*["\'](?P<pwd>\S+)["\']', [] ),
# Rule( 'password-random-windomain', 'password', '(?P<pwd>' + '[\w\.]{2,32}\\\w{1,20}:' + pwd + '{2,32})', [] ),
# Rule( 'password-windomain', 'password', '(?P<pwd>' + '<domain>\\\w{1,20}:' + pwd + '{2,32})', ['domain'] ),
# Rule( 'pbhash1', 'password hash', '(?P<pwd>[a-fA-F0-9]{16,}:' + emailAtDomain + ')', ['domain'] ),
# Rule( 'pbhash2', 'password hash', '(?P<pwd>' + emailAtDomain + ':[a-fA-F0-9]{16,})', ['domain'] ),
# Rule( 'pbhash3', 'password hash', '(?P<pwd>[a-fA-F0-9]{16,},' + emailAtDomain + ')', ['domain'] ),
# Rule( 'pbhash4', 'password hash', '(?P<pwd>' + emailAtDomain + ',[a-fA-F0-9]{16,})', ['domain'] ),
# Rule( 'pbhash5', 'password hash', '(?P<pwd>[a-fA-F0-9:]{16,}\s*|\s*' + emailAtDomain + ')', ['domain'] ),
# Rule( 'pbhash6', 'password hash', '(?P<pwd>' + emailAtDomain + '\s*|\s*[a-fA-F0-9:]{16,})', ['domain'] ),
# Rule( 'pbhash7', 'password hash', '(?P<pwd>[a-fA-F0-9:]{16,}\s*' + emailAtDomain + ')', ['domain'] ),
# Rule( 'pbpassword', 'password', '(?P<pwd>' + emailAtDomain + ':[^\s\'">]+)', ['domain'] ),
# Rule( 'pbpassword2', 'password', '(?P<pwd>' + emailAtDomain + '|[^\s\'">]+)', ['domain'] ),
# Rule( 'phone-us', 'phone', '(?P<pwd>' + '\d{3}[\s-]?\d{3}[\s-_]?\d{4}' + ')', [] ),
# Rule( 'sshpass', 'password', 'sshpass\s+.{,80}-p\s*(?P<pwd>\S+)', [] ),
# Rule( 'ssn (US)', 'ssn', '(?P<pwd>' +"[0-9]{3}[ -]?[0-9]{2}[ -]?[0-9]{4}" + ')', [] ),
# Rule( 'timestamp-recent', 'timestamp', '(?P<timestamp>' + str(int(time.time()))[:2] + '\d{8}' + ')', [] ),
# Rule( 'US Passport Number', 'passport', '(?P<pwd>' + "[23][0-9]{8}" + ')', [] ),


# Remove filelists, as not relevant to assessments
rm_if_present "$APPLE_FILELIST"
rm_if_present "$C_FILELIST"
rm_if_present "$CS_FILELIST"
rm_if_present "$GO_FILELIST"
rm_if_present "$JAVA_FILELIST"
rm_if_present "$PHP_FILELIST"
rm_if_present "$RUBY_FILELIST"
rm_if_present "$PYTHON_FILELIST"

do_exec 'echo `date`' 'basic_finished.txt'

finish_time=$(date +%s)
time_taken=$((finish_time - start_time))
do_exec "echo $time_taken" 'basic_time_taken.txt'

info "=====> DONE!"

[[ -z "$(jobs -r)" ]] || warn "Tasks may still be running."

exit 1