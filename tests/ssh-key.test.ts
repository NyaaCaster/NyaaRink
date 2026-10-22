import { expect, it, vi } from 'vitest';
import ssh2 from 'ssh2';
import { sshKeyPair } from '../apps/server/src/ssh-key.js';

it('rejects malformed and mismatched generated keys before accepting a usable pair', () => {
  const pair = sshKeyPair(), other = sshKeyPair();
  const generate = vi.fn().mockReturnValueOnce({ private: 'invalid', public: pair.public })
    .mockReturnValueOnce({ private: pair.private, public: other.public }).mockReturnValue(pair);
  expect(sshKeyPair(generate)).toEqual(pair);
  expect(generate).toHaveBeenCalledTimes(3);
  const parsed = ssh2.utils.parseKey(pair.private);
  expect(parsed).not.toBeInstanceOf(Error);
});

it('fails closed after bounded generation attempts without exposing key material', () => {
  const generate = vi.fn(() => ({ private: 'invalid-private', public: 'invalid-public' }));
  expect(() => sshKeyPair(generate)).toThrow('Unable to generate a valid SSH key pair');
  expect(generate).toHaveBeenCalledTimes(8);
});
