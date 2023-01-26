# grep_all

> A shell script that runs grep to find security-relevant things.
>

**WARNING: THIS SCRIPT MAY DAMAGE YOUR COMPUTER. RUN IT AT YOUR OWN RISK.**

## Overview

`grep_all` is a standalone shell script that attempts to identify numerous security flaws in source code. It uses regular expressions to identify insecure patterns in source code, writing the results to a target directory. 

Targetted analysis includes:

* C/C++
* C#
* PHP
* Ruby
* Java
* Python

Other global checks are performed, which are globally applicable across languages. Examples include:

* Credentials in code
* Insecure URL strings (http:)
* Insecure SQL-like syntax
* .. and many many others 

`grep_all` does not using any sematic analysis or compilation - it is purely using regular expressions, sometimes multiple, to filter the data down. 

## Usage

Simply download/copy the file to your audit directory and use the commands below. Or, copy it to your `~/bin` path to use it anytime.

The command format is:
```bash
grep_all.sh [-v] [-r] <output directory> [code directory]
```

The script takes 4 parameters:

```bash
      -v/--verbose      :   (Optional) Enable verbose messages
      -r/--ripgrep      :   (Optional) Use rg instead of grep to perform regex matches
      <output directory>:   The location to write the results
      [code directory]  :   (Optional) The location of code to audit
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

If you have ripgrep (rg) installed, specify `-r`/`--ripgrep` to get a performance improvement:

```
grep_all.sh -r ~/path/to/output
```

## Remarks

This script can take a long time to run. If you terminate the script, then rerun with the same arguments. If it is terminated early, you may lose the output from the command(s) currently running. However, the script will generally pick up where they left off.

As with all code review tooling, ***false positives should be expected*** and the auditor/reviewer/developer should take this into account. 

## Other useful information

`grep_all` will attempt to run several other tools installed locally. These are not required, and will be skipped if unavailable.

* bandit
* brakeman
* eslint
* clamav
* cloc
* flawfinder
* php_metrics
* npm audit
* retirejs
* safety


