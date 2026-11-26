# Changelog

Format mengikuti [Keep a Changelog](https://keepachangelog.com/); versi mengikuti [SemVer](https://semver.org/).

## [0.2.0] - 2026-11-26

Rilis hardening keamanan sebelum dipublikasikan sebagai open source.

### Security
- **Masking PII di log** (`--mask-pii auto|on|off`): NIK, nama, alamat, telepon, e-mail, tanggal lahir, dan parameter query pencarian. `auto` (default) = aktif untuk upstream production. Trafik yang diteruskan ke SATUSEHAT tidak pernah diubah.
- Redaksi secret (`client_secret`, token, password, `Bearer ...`) kini **selalu aktif**, termasuk body non-JSON dan `error_summary`.
- Log dibuat dengan permission **0600** (direktori **0700**), tanpa mengikuti symlink; opsi `log_file_mode` untuk akses grup (640).
- File clipboard fallback dipindah dari `/tmp` (nama dapat ditebak) ke direktori privat per-user dan **dihapus saat TUI keluar**.
- **Perbaikan bug/celah** pada perintah cURL hasil copy: body dan URL kini di-quote dengan `shlex.quote` (sebelumnya tanda kutip tunggal pada data dapat merusak atau menyisipkan perintah shell).
- Batas ukuran request/response (`max_body_mb`), batas koneksi paralel, timeout klien lambat, penanganan `Content-Length`/chunked yang malformed, dan batas dekompresi gzip.
- Proxy menolak bind ke alamat non-loopback tanpa `--allow-remote`; menolak `--insecure` untuk host production; upstream `http://` hanya diterima untuk loopback (pengujian).
- `/_health` tidak lagi membocorkan path direktori log.
- Karakter kontrol terminal pada data log dinetralkan sebelum digambar di TUI.
- ID transaksi memakai SHA-256 (sebelumnya MD5).
- Unit systemd diperketat (user khusus, `ProtectSystem=strict`, `NoNewPrivileges`, dst.).

### Added
- Batas ukuran log harian (`max_daily_log_mb`) dan batas payload yang disimpan (`max_logged_body_kb`).
- Konfirmasi untuk `--clear-logs` (`--yes` untuk non-interaktif).
- Test suite (`python3 -m unittest discover -s tests -t .`), CI (test, Bandit, CodeQL, OpenSSF Scorecard), `SECURITY.md`, `CONTRIBUTING.md`, `LICENSE` (MIT).

### Changed
- Python minimal **3.10** (3.9 sudah end-of-life).
- Dokumentasi diluruskan: viewer tidak "read-only mutlak" (ada fitur hapus log yang eksplisit).

### Removed
- File log contoh dan `__pycache__` dari paket distribusi.

## [0.1.0]
- Rilis internal awal.
