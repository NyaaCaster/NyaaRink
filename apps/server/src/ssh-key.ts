import ssh2 from 'ssh2';

const { utils } = ssh2;
type Pair = { private: string; public: string };

// ssh2 1.17 can strip an Ed25519 public key's leading zero byte while encoding.
// Never persist that malformed pair or weaken the algorithm to work around it.
export function sshKeyPair(generate: () => Pair = () => utils.generateKeyPairSync('ed25519')): Pair {
  for (let attempt = 0; attempt < 8; attempt++) {
    const pair = generate(), secret = utils.parseKey(pair.private), publicKey = utils.parseKey(pair.public);
    if (secret instanceof Error || publicKey instanceof Error || Array.isArray(secret) || Array.isArray(publicKey)) continue;
    if (secret.type === 'ssh-ed25519' && secret.isPrivateKey() && secret.getPublicSSH().equals(publicKey.getPublicSSH())) return pair;
  }
  throw new Error('Unable to generate a valid SSH key pair');
}
