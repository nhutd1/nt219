#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>

using namespace CryptoPP;

void performECDHE() {
    AutoSeededRandomPool prng;

    // Domain parameters for ECDHE
    DL_GroupParameters_EC<ECP> params(ASN1::secp256r1());

    // Generate keys
    ECDH<ECP>::Domain dh(params);
    SecByteBlock priv(dh.PrivateKeyLength()), pub(dh.PublicKeyLength());
    dh.GenerateKeyPair(prng, priv, pub);

    // Exchange keys and derive shared secret (normally, pub would be sent to the peer)
    SecByteBlock shared(dh.AgreedValueLength());
    if (!dh.Agree(shared, priv, pub))
        throw std::runtime_error("Failed to reach shared secret");
}
