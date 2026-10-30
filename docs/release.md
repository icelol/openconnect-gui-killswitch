# Release packaging / Выпуск релиза

`VERSION` is authoritative for both platforms. Installer metadata, README links
and release notes must agree. Keep published tags and binaries immutable.

1. Commit source and run `python3 scripts/validate-release.py`.
2. On Apple Silicon run `sh scripts/build-macos.sh`: safety/UI tests, PKG, DMG,
   bundle validation and corresponding modified OpenConnect source.
3. Build Windows through `.github/workflows/windows.yml` or MSYS2 UCRT64 with
   `sh scripts/build-windows.sh`. Run networking QA only on the disposable Windows
   CI runner and preserve its commit/run URL and `windows-verification.json`.
4. Audit actual installers, versions, signatures/dependencies, public CA,
   cleanup/recovery, license notices, corresponding source inputs and privacy.
   A mock gateway or package build does not prove target VPN compatibility.
5. Put both installers, exact dependency sources, GUI source ZIP and verification
   reports in `dist/`. Run `./release.sh`, then
   `python3 scripts/assemble-release.py --check`.
6. Publish the reviewed commit/tag, manifest files, `RELEASE-MANIFEST.json`,
   `SHA256SUMS` and checksum sidecars. Download every published file and verify
   SHA-256 and the remote source/tag. Protected GitLab main uses a reviewed MR.

`release.sh` is an offline assembler: it reads no tokens, creates no tags, pushes
no repositories and never contacts upstream maintainers' publication servers.
Publishing uses the explicitly selected account/repository. Credentials and
organization-specific profiles never belong in source, installers or reports.

Обе платформы используют одну версию из `VERSION` и проверенный коммит. После
сборки проверяются реальные EXE, PKG/DMG, восстановление/удаление, лицензии,
соответствующие исходники и отсутствие частных данных. `release.sh` создаёт
локальные `RELEASE-MANIFEST.json` и `SHA256SUMS`; публикаций и чтения токенов в нём
нет. После публикации заново скачайте файлы и проверьте хеши, тег и исходники.
Уже опубликованные файлы старых релизов сохраняются.
