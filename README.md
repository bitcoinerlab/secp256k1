<!--Related:
https://github.com/paulmillr/noble-secp256k1/issues/73
https://github.com/bitcoinjs/ecpair/issues/13
https://github.com/bitcoinjs/ecpair/pull/11
https://github.com/bitcoinjs/tiny-secp256k1/issues/91
https://github.com/bitcoinjs/tiny-secp256k1/issues/84#issuecomment-1210013688
Test this: https://github.com/spsina/bip47
-->

# Secp256k1

@bitcoinerlab/secp256k1 is a Javascript library for performing elliptic curve operations on the secp256k1 curve. It is designed to integrate into the [BitcoinJS](https://github.com/bitcoinjs) and [BitcoinerLAB](https://bitcoinerlab.com) ecosystems and uses the audited [noble-curves library](https://github.com/paulmillr/noble-curves), created by [Paul Miller](https://paulmillr.com/noble/).

 This library is compatible with environments that do not support WebAssembly, such as React Native.

## Features

- Compatible with BitcoinJS [ecpair](https://github.com/bitcoinjs/ecpair) and [bip32](https://github.com/bitcoinjs/bip32) Factory functions.
- Based on audited code [@noble/secp256k1](https://github.com/paulmillr/noble-secp256k1).
- Can be used in environments that do not support WASM, such as React Native.
- Uses the same tests as [tiny-secp256k1](https://github.com/bitcoinjs/tiny-secp256k1).

## Installation

To install the package, use npm:

```
npm install @bitcoinerlab/secp256k1
```

## Usage

### API

This implementation follows the tiny-secp256k1 API. Please refer to [tiny-secp256k1](https://github.com/bitcoinjs/tiny-secp256k1#documentation) for documentation on the methods.

- **`xOnlyPointAddTweakCheck`**: This method is not yet implemented. It is not used in `ecpair` or `bip32`.

- **`signSchnorr`**: Starting from version 1.2.0, this function deviates from the exact behavior mapping with [`bitcoinjs/tiny-secp256k1`](https://github.com/bitcoinjs/tiny-secp256k1) and no longer initializes the auxiliary random data parameter (`e`) to a zero-filled array by default. Instead, it requires the caller to explicitly provide randomness if desired. If omitted, the underlying implementation uses cryptographically secure randomness (through `crypto.getRandomValues`). For more details on this change, see the discussion [here](https://github.com/bitcoinerlab/secp256k1/pull/10#discussion_r1876541974) and the conclusions [here](https://github.com/bitcoinerlab/secp256k1/pull/10#issuecomment-2537916286).

### Examples

You can test the examples in this section using the online playground demo available at https://bitcoinerlab.com/modules/secp256k1.

```javascript
import ecc from '@bitcoinerlab/secp256k1';
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
```

### Usage with React Native

@noble/secp256k1 uses Javascript `BigInt`, which is fully supported in React Native on iOS. However, to use it on Android, you must make sure you use the Hermes Javascript Engine, available from [RN-0.70 release](https://github.com/facebook/hermes/issues/510).

## Authors and Contributors

The project was initially developed and is currently maintained by [Jose-Luis Landabaso](https://github.com/landabaso). Contributions and help from other developers are welcome.

Here are some resources to help you get started with contributing:

### Building from source

To download the source code and build the project, follow these steps:

1. Clone the repository:

```
git clone https://github.com/bitcoinerlab/secp256k1.git
```

2. Install the dependencies:

```
npm install
```

3. Build the project:

```
npm run build
```

This will build the project and generate the necessary files in the `dist` directory.

### Testing

Before committing any code, make sure it passes all tests by running:

```
npm run test
```

## Licensing

This project is licensed under the MIT License.

## Acknowledgments

Thanks to Paul Miller for creating and maintaining the noble-secp256k1 library, upon which this library is based.

Thanks to the BitcoinJS team for creating and maintaining the BitcoinJS ecosystem, including the ecpair and bip32 libraries, which this library is designed to integrate with.

Thanks to the tiny-secp256k1 team for creating and maintaining the tiny-secp256k1 library, which this library uses for testing.
