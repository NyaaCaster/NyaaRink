# NyaaRink distribution notices

NyaaRink source is licensed under AGPL-3.0; see LICENSE. Corresponding source and build instructions: https://github.com/NyaaCaster/NyaaRink

Client distributions include the official Node.js runtime, with its full license and bundled component notices in NODE-LICENSE.

The bundled client JavaScript includes ssh2 (MIT), ssh2-streams protocol code incorporated in ssh2 (MIT), asn1 (MIT), safer-buffer (MIT), bcrypt-pbkdf (BSD-3-Clause), tweetnacl (public domain), ws (MIT), Zod (MIT) and NyaaRink workspace code (AGPL-3.0).

Full dependency copyright/license texts are appended during distribution assembly from the locked installed packages. Optional native CPU/crypto accelerators are excluded; the client uses the Node.js crypto implementation and pure JavaScript dependencies.

Server and CLI builds include `dist/licenses/dependencies.json` (installed production dependency versions and license identifiers) and `dist/licenses/THIRD-PARTY-NOTICES.txt` (full package license/notice texts), generated reproducibly by `node scripts/licenses.mjs`. Production containers include these files together with the project LICENSE. Node.js and OS package notices remain available in the base image's standard license locations. The web bundle retains esbuild/Vite legal comments for bundled components; React and React DOM full texts are also included in the production dependency notices.
