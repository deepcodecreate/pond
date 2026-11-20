# Pond

Android app that inspects device signals: key attestation, TEE, kernel and environment probes. It reports signals only. It is not a Play Integrity verdict and does not prove a device is unmodified.

[![Get it in Lumen Store](https://deepcodecreate.github.io/lumenstore/badges/lumen-store.svg)](https://deepcodecreate.github.io/lumenstore/app.html?id=com.pond.inspector)

## Requirements

- JDK 17
- Android SDK with platform 36
- Gradle 8.14+ (or generate the wrapper with `gradle wrapper --gradle-version 8.14.3`)

## Build

```
gradle :app:assembleDebug
gradle :app:testDebugUnitTest
gradle :app:assembleRelease
```

The release build is signed with a keystore generated on first build (`app/release.keystore` and `app/keystore.properties`). Both are git-ignored. Keep them private and back them up if you distribute releases, since updates must be signed with the same key.

## Languages

English and Persian.

## License

Pond is free software licensed under the GNU General Public License v3.0 or later. See [LICENSE](LICENSE).

Copyright (C) 2026 @deepcodecreate
