# NyaaRink distribution notices

NyaaRink source is licensed under AGPL-3.0; see LICENSE. Corresponding source and build instructions: https://github.com/NyaaCaster/NyaaRink

Client distributions include the official Node.js runtime, with its full license and bundled component notices in NODE-LICENSE.

The bundled client JavaScript includes ssh2 (MIT), ssh2-streams protocol code incorporated in ssh2 (MIT), asn1 (MIT), safer-buffer (MIT), bcrypt-pbkdf (BSD-3-Clause), tweetnacl (public domain), ws (MIT), Zod (MIT) and NyaaRink workspace code (AGPL-3.0).

Full dependency copyright/license texts are appended during distribution assembly from the locked installed packages. Optional native CPU/crypto accelerators are excluded; the client uses the Node.js crypto implementation and pure JavaScript dependencies.
