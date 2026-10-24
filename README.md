# Craft CMS 2026 PoCs

Proof-of-concept exploits accompanying my Craft CMS writeups, discovered by CryptoCat ([cryptocat.me](https://cryptocat.me)). Every issue below is fixed.

| Script | Finding | Access | CVE / Advisory | Writeup |
| --- | --- | --- | --- | --- |
| `signed_redirect_rce.py` | Signed-cookie/redirect confusion to Twig SSTI | Any login | [CVE-2026-92592](https://nvd.nist.gov/vuln/detail/CVE-2026-92592) | [Writeup](https://cryptocat.me/blog/research/analysis/craftcms_signed_redirect_rce/) |
| `db_failopen_rce.py` | Installer fail-open environment disclosure to RCE | None (during a database outage) | [CVE-2026-92591](https://nvd.nist.gov/vuln/detail/CVE-2026-92591) | [Writeup](https://cryptocat.me/blog/research/analysis/craftcms_db_failopen_rce/) |
| `eagerload_graphql_unauth_rce.py` | GraphQL eager-load callback to OS command execution | None | [CVE-2026-79987](https://nvd.nist.gov/vuln/detail/CVE-2026-79987) | [Writeup](https://cryptocat.me/blog/research/analysis/craftcms_eagerload_rce/) |
| `eagerload_authenticated_rce.py` | Element-search eager-load callback to OS command execution | `accessCp` | [CVE-2026-79987](https://nvd.nist.gov/vuln/detail/CVE-2026-79987) | [Writeup](https://cryptocat.me/blog/research/analysis/craftcms_eagerload_rce/) |
| `eagerload_graphql_unauth_sqli.py` | GraphQL eager-load `select` criteria to SQL injection | None | [GHSA-mjj9-pjh4-r48g](https://github.com/craftcms/cms/security/advisories/GHSA-mjj9-pjh4-r48g) | [Writeup](https://cryptocat.me/blog/research/analysis/craftcms_eagerload_sqli/) |

Both eager-load scripts reach the same untyped `EagerLoadPlan::$when` property, so they share CVE-2026-79987. Its advisory, [GHSA-9c4j-cjw3-r3xx](https://github.com/craftcms/cms/security/advisories/GHSA-9c4j-cjw3-r3xx), describes only the authenticated route. The installer advisory [GHSA-hfjh-gw6x-7pv5](https://github.com/craftcms/cms/security/advisories/GHSA-hfjh-gw6x-7pv5) covers the disclosure, and the RCE reuses the redirect sink documented in [GHSA-5r92-75j8-c534](https://github.com/craftcms/cms/security/advisories/GHSA-5r92-75j8-c534).

## Usage

Client side: Python 3 and `requests`. Each script is standalone (one file, no shared module) and takes a target and a `--command`, or a `--query` for the SQL injection. Progress goes to stderr and results to stdout, and each supports `-h/--help` and `--no-color`. Run only against systems you are authorised to test.

Target side, the command payloads assume a POSIX shell (`sh`, `printf`) and `base64 -d`. They are written for the usual Linux Craft host, not a Windows-hosted or stripped-down target.

```bash
pip install requests

python3 signed_redirect_rce.py --url https://target --username user --password pass --command id
python3 db_failopen_rce.py --url https://target --command id   # polls, fires during a DB outage
python3 eagerload_graphql_unauth_rce.py --url https://target --command id
python3 eagerload_authenticated_rce.py -u https://target/admin -U editor -p pass -c id
python3 eagerload_graphql_unauth_sqli.py --url https://target --query "@@version"
```

The GraphQL scripts need a public schema that exposes an asset volume but not user groups, one asset with a populated uploader, and MySQL.

Affected: Craft CMS `>= 5.8.0, < 5.10.13` for the element-search eager-load route and `>= 5.0.0, < 5.10.13` for the GraphQL one (both fixed in 5.10.13), before 5.11.2 and 4.18.9 for the eager-load SQL injection, `>= 5.0.0, < 5.10.13` for the installer disclosure, and `>= 5.0.0, < 5.10.13` and `>= 4.8.0, < 4.18.6` for the signed redirect.
