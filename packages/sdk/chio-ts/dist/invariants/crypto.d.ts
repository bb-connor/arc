export declare function sha256Hex(input: string | Buffer): string;
export declare function isValidEd25519PublicKeyHex(publicKeyHex: string): boolean;
export declare function isValidEd25519SignatureHex(signatureHex: string): boolean;
export declare function publicKeyHexMatches(left: string, right: string): boolean;
export declare function signEd25519Message(message: string | Buffer, seedHex: string): {
    public_key_hex: string;
    signature_hex: string;
};
export declare function verifyEd25519Signature(message: string | Buffer, publicKeyHex: string, signatureHex: string): boolean;
//# sourceMappingURL=crypto.d.ts.map