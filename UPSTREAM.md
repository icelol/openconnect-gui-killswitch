# Upstream and licenses

This project is based on [OpenConnect-GUI](https://gitlab.com/openconnect/openconnect-gui)
1.6.2, commit `f210cb56fe561cd25b1b5bc12bf40c3966a03046`.
Version **1.1.0** identifies this public fork with an independent macOS network service.
Original copyright notices, [AUTHORS](AUTHORS) and [LICENSE.txt](LICENSE.txt) are preserved.
The project license is GPL-2.0-or-later.

The public repository starts from a sanitized source snapshot. It does not import
organization-specific deployment history, runtime profiles or credentials.

The client uses libOpenConnect, GnuTLS, Qt, QtSingleApplication and spdlog.
The build bundles the required dynamic libraries. The current local build uses
OpenConnect 9.21, GnuTLS 3.8.13, Qt 6.12.0 and spdlog 1.17.0.
QtSingleApplication is pinned to Qt Solutions commit
`777e95ba69952f11eaec0adfb0cb987fabcdecb3`.
Homebrew supplies the library packages and their source/build metadata.

PF state handling uses public Apple XNU structures and information from pfctl-rs.
The MIT notice is preserved in
[docs/third-party/pfctl-rs-MIT.txt](docs/third-party/pfctl-rs-MIT.txt) and included in
the application bundle. TLS certificates come from the unmodified vendor CA bundle;
local custom trust-store additions are not distributed.
