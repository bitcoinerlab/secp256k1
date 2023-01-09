import ecc from './dist/index.js';
import { BIP32Factory } from 'bip32';
import { ECPairFactory } from 'ecpair';
const BIP32 = BIP32Factory(ecc);
const ECPair = ECPairFactory(ecc);

const keyPair1 = ECPair.fromWIF(
  'KynD8ZKdViVo5W82oyxvE18BbG6nZPVQ8Td8hYbwU94RmyUALUik'
);
const node = BIP32.fromBase58(
  'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
);
console.log({ node, keyPair1 });
