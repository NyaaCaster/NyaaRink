import { connect } from 'node:net';
import { isAbsolute } from 'node:path';
const path = process.argv[2];
if (!path || !isAbsolute(path) || process.platform === 'win32') process.exitCode = 2;
else {
  const socket = connect(path);
  const timer = setTimeout(() => socket.destroy(new Error('Proxy timeout')), 30000);
  socket.once('connect', () => clearTimeout(timer));
  socket.on('error', () => { process.stderr.write('NyaaRink SSH proxy unavailable\n'); process.exitCode = 1; });
  socket.once('close', () => { clearTimeout(timer); process.stdin.unpipe(socket); process.stdin.pause(); });
  process.stdout.on('error', () => socket.destroy());
  process.stdin.pipe(socket).pipe(process.stdout);
}
