# grep_all

> A shell script that runs grep to find security-relevant things.
>

**WARNING: THIS SCRIPT MAY DAMAGE YOUR COMPUTER. RUN IT AT YOUR OWN RISK.**

## Overview

`grep_all` is a standalone shell script that attempts to identify numerous security flaws in source code. It uses regular expressions to identify insecure patterns and produces a number of files in relation to each issue found. 

The script has a number of rules for specific languages, such as:

* C/C++
* C#
* PHP
* Ruby
* Java
* Python

The remaining checks occur across all text files, many of which are applicable across languages. Violations include:

* Credentials in code
* TODO-style comments
* Insecure URL strings (http:)
* Insecure SQL-like syntax
* .. and many many others 

`grep_all` does not using any sematic analysis or compilation processes - it is just regular expression matches, sometimes multiple filters tied together, to produce the final results. 

## Usage

Simply download/copy the file to your audit directory and use the commands below. Or, copy it to your `~/bin` path to use it anytime.

The command format is:
```bash
grep_all.sh [-h] [-v] [-r] <output directory> [code directory]
```

The script takes 4 parameters:

```bash
   -h/--help          : (Optional) Shows the help message
   -v/--verbose       : (Optional) Enable verbose messages, showing all operations
   -r/--ripgrep       : (Optional) Use rg instead of grep
   <output directory> : The location to write the results
   [code directory]   : (Optional) The location of code to audit
```

To grep_all (audit) the current directory, just specify the output path:

```bash
cd /mnt/project/src/code
grep_all.sh ~/path/to/output
```

To audit a specific directory, provide both the output path and code path:

```bash
grep_all.sh ~/path/to/output ~/path/to/code
```

If you have ripgrep (rg) installed, specify `-r`/`--ripgrep` to get a performance boost:

```bash
grep_all.sh -r ~/path/to/output
```

## Remarks

This script can take a long time to run. If you terminate the script, then rerun it with the same arguments. If it is terminated early, you may lose the output from the command(s) currently running. However, the script will generally pick up where they left off.

As with all code review tooling, ***false positives should be expected*** and the auditor/reviewer/developer should take this into account. 


## Recent updates

### Jan-2023

* Fixed a check that was not working - `bug_url_numeric.txt`.
* Fixed parameter globbing issue in `do_fast_banned_grep()` function.
* Added debug mode, and retrofitted where immediately relevant.
* Refactored cmd argument flags.
* Ran script against [shellcheck](https://www.shellcheck.net/) and corrected errors and warnings.
* Added warning at the end if any tools started by the script are still running.

Other improvements include:

* Improved grep performance against known file types. These are cached upfront
* Added `-v`/`--verbose` flag for extended information on what processing is taking place.
* Added rules include:
  * C# Check for `[Obsolete]` attributes, i.e. intentionally deprecated methods
  * C# Check for `ServerCertificateValidationCallback`, used to validate SSL certificates.
* Modified rules include:
  * Domain name checks; now include more TLDs, and check on word boundary instead of globally.
  * Exclude filters: no longer process files in `/bin/` and `/obj/` folders.

## Other useful information

### Third-party tools

`grep_all` will attempt to run several other tools installed locally. These are not required, and will be skipped if unavailable.

#### C/C++
* flawfinder: https://dwheeler.com/flawfinder/

#### General
* clamav: https://www.clamav.net/
* cloc: https://cloc.org/

#### JavaScript
* npm audit: https://docs.npmjs.com/cli/v9/commands/npm-audit
* retirejs: https://retirejs.github.io/retire.js/
* eslint: https://eslint.org/

#### PHP
* php_metrics: https://www.phpmetrics.org/

#### Python
* bandit: https://pypi.org/project/bandit/
* safety: https://pypi.org/project/safety/
   
#### Ruby
* brakeman: https://brakemanscanner.org/

### Debugging 

`grep_all` has a `-d`/`--debug` flag, provided as one of the first parameters. This output is useful for understanding the *state* of the application, in particular parameters into/out of functions. 
