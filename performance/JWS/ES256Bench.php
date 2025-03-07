<?php

declare(strict_types=1);

namespace Jose\Performance\JWS;

use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use Override;
use PhpBench\Benchmark\Metadata\Annotations\Groups;
use PhpBench\Benchmark\Metadata\Annotations\Revs;

/**
 * @Revs(4096)
 * @Groups({"JWS", "ECDSA", "ES256"})
 */
final class ES256Bench extends SignatureBench
{
    public function dataSignature(): array
    {
        return [
            [
                'algorithm' => 'ES256',
            ],
        ];
    }

    public function dataVerification(): array
    {
        return [
            [
                'input' => 'eyJhbGciOiJFUzI1NiJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.PQcIuf_bZFoOChBj7z_6KQlfpfvZ4YSUvtVheoAKQJ_rjywLft5dqL79bOrGffW0CkGPvaKzBr3yGdQt3II54g',
            ],
        ];
    }

    public function dataVerify(): array
    {
        return [
            [
                'signature' => 'PQcIuf_bZFoOChBj7z_6KQlfpfvZ4YSUvtVheoAKQJ_rjywLft5dqL79bOrGffW0CkGPvaKzBr3yGdQt3II54g',
            ],
        ];
    }

    #[Override]
    protected function getAlgorithm(): SignatureAlgorithm
    {
        return $this->getSignatureAlgorithmsManager()
            ->get('ES256')
        ;
    }

    #[Override]
    protected function getInput(): string
    {
        return 'eyJhbGciOiJFUzI1NiJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4';
    }

    #[Override]
    protected function getPrivateKey(): JWK
    {
        return new JWK([
            'kty' => 'EC',
            'kid' => 'meriadoc.brandybuck@buckland.example',
            'use' => 'sig',
            'crv' => 'P-256',
            'x' => 'Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0',
            'y' => 'HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw',
            'd' => 'r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8',
        ]);
    }

    #[Override]
    protected function getPublicKey(): JWK
    {
        return $this->getPrivateKey()
            ->toPublic()
        ;
    }
}
