# Demo pages

Harmless training pages for the PhishGuard demonstration. Nothing is stored; the "collector" discards form data.

## Setup (once)
Add host names that point at your own machine. Edit the hosts file as administrator
(Windows: `C:\Windows\System32\drivers\etc\hosts`, Linux/macOS: `/etc/hosts`):

```
127.0.0.1  cbe-birr-login.test
127.0.0.1  prize-claim.test
127.0.0.1  inbox.test
127.0.0.1  bakery.test
127.0.0.1  collector.test
```

## Run
1. `python server.py` (in the project root) and `python demo/serve.py`
2. Visit, with the extension loaded:

| URL | Shows | Expected |
|---|---|---|
| `http://bakery.test:8080/benign.html` | ordinary page with a form | Safe |
| `http://cbe-birr-login.test:8080/clone_bank.html` | brand mismatch + password + external form | Dangerous full-page warning |
| `http://prize-claim.test:8080/amharic_scam.html` | Amharic and English scam wording | Suspicious banner |
| `http://inbox.test:8080/links.html` | hover over links (do not click) | tooltips on the bad links only |

Note: `.test` is a reserved domain that never resolves publicly, and the pages are served over plain HTTP,
so the engine also adds the small no-HTTPS signal. Record each result and take screenshots for the report.
